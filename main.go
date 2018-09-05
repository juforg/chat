package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	. "qychat_middleware/config"
	"strconv"
	"strings"
	"time"

	"fmt"
	"github.com/kataras/go-errors"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
	"github.com/patrickmn/go-cache"
	"io"
	"mime/multipart"
)

var (
	//WorkPath       = GetWorkPath()

	//GetConfig      = goini.SetConfig(WorkPath + "config.conf")
	//corpId         = GetConfig.GetValue("weixin", "CorpID")
	//agentId        = GetConfig.GetValue("weixin", "AgentId")
	//secret         = GetConfig.GetValue("weixin", "Secret")
	//EncodingAESKey = GetConfig.GetValue("weixin", "EncodingAESKey")

	TokenCache *cache.Cache
	config     Conf
)

const (
	WechatUploadMediaAPI = "https://qyapi.weixin.qq.com/cgi-bin/media/upload"
)

type MediaUpload struct {
	ErrCode   int    `json:"errcode"`
	ErrMgs    string `json:"errmsg"`
	Type      string `json:"type"`
	MediaID   string `json:"media_id"`
	CreatedAt string `json:"created_at"`
}

func init() {
	TokenCache = cache.New(6000*time.Second, 5*time.Second)
}

func main() {
	config := config.GetConf()
	go GetAccessTokenFromWeixin()

	e := echo.New()
	e.Logger.SetLevel(log.INFO)
	e.Use(middleware.Logger())
	e.GET("/auth", WxAuth)
	e.GET("/uploadpage", UploadPage)
	e.GET("/getuserinfo", GetUserInfo)
	e.POST("/send", SendMsg)
	e.POST("/sendMedia", SendMedia)

	port := config.Http.Port
	//port := GetConfig.GetValue("http", "port")
	if port == "no value" {
		e.Logger.Fatal(e.Start("0.0.0.0:4567"))
	} else {
		e.Logger.Fatal(e.Start("0.0.0.0:" + port))
	}
}

//发送信息
type Content struct {
	Content string `json:"content"`
}
type MediaContent struct {
	MediaId string `json:"media_id"`
}

type MsgPost struct {
	ToUser  string  `json:"touser"`
	MsgType string  `json:"msgtype"`
	AgentID int     `json:"agentid"`
	Text    Content `json:"text"`
}
type MediaPost struct {
	MsgPost
	ToParty string       `json:"toparty"`
	ToTag   string       `json:"totag"`
	Image   MediaContent `json:"image"`
}
type RetData struct {
	RetCode string `json:"retCode"`
	RetMsg  string `json:"retMsg"`
}

func UploadPage(context echo.Context) error {

	return context.HTML(http.StatusOK, string(`<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Single file upload</title>
</head>
<body>
<h1>Upload single file with fields</h1>

<form action="/sendMedia" method="post" enctype="multipart/form-data">
    Name: <input type="text" name="name"><br>
    工号: <input id="tos" type="tos" name="tos"><br>
    Files: <input type="file" name="mediafile"><br><br>
    <input type="submit" value="上传附件">
	<input type="button" value="获取个人信息" onclick="GetUserInfo()">
</form>
<script>
function GetUserInfo(){
tos = document.getElementById("tos").value;
window.location= "/getuserinfo?workno="+tos;
}
</script
</body>
</html>`))
}

func SendMsg(context echo.Context) error {
	toUser := context.FormValue("tos")
	content := context.FormValue("content")
	//content := "[P0][OK][192.168.11.26_ofmon][][【critical】与主mysql同步延迟超过10s！ all(#3) seconds_behind_master port=3306 0>10][O1 2017-04-17 08:55:00]"
	content = strings.Replace(content, "][", "\n", -1)
	if content[0] == '[' {
		content = content[1:]
	}

	if content[len(content)-1] == ']' {
		content = content[:len(content)-1]
	}

	if userList := strings.Split(toUser, ","); len(userList) > 1 {
		toUser = strings.Join(userList, "|")
	}

	text := Content{}
	text.Content = content

	msg := MsgPost{
		ToUser:  toUser,
		MsgType: "text",
		AgentID: StringToInt(config.Weixin.AgentId),
		Text:    text,
	}

	token, found := TokenCache.Get("token")
	if !found {
		log.Printf("token获取失败!")
		return context.String(200, "token获取失败!")
	}
	accessToken, ok := token.(AccessToken)
	if !ok {
		return context.String(200, "token解析失败!")
	}

	url := "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=" + accessToken.AccessToken
	jsonBody, err := encodeJson(msg)
	if err != nil {
		return context.String(200, "token解析失败!")
	}
	result, err := WxPost(url, jsonBody)
	if err != nil {
		log.Printf("请求微信失败: %v", err)
	}
	log.Printf("发送信息给%s, 信息内容: %s, 微信返回结果: %v", toUser, content, result)
	return context.String(200, string(result))
}

func SendMedia(c echo.Context) error {
	//filename := c.FormValue("filename")
	retData := RetData{}
	toUser := c.FormValue("tos")
	file, err := c.FormFile("mediafile")
	if err != nil {
		return err
	}
	if file.Size > (2*1024*1024) || file.Size <= 0 {
		retData.RetCode = "401"
		retData.RetMsg = "图片不能大于2M!"
		return c.JSON(200, retData)
	}
	src, err := file.Open()
	if err != nil {
		fmt.Println("error opening file")
		retData.RetCode = "501"
		retData.RetMsg = err.Error()
		return c.JSON(200, retData)
	}
	defer src.Close()
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	//关键的一步操作
	fileWriter, err := bodyWriter.CreateFormFile("media", file.Filename)
	if err != nil {
		fmt.Println("error writing to buffer")
		retData.RetCode = "501"
		retData.RetMsg = err.Error()
		return c.JSON(200, retData)
	}
	_, err = io.Copy(fileWriter, src)
	err = bodyWriter.Close()
	if err != nil {
		retData.RetCode = "501"
		retData.RetMsg = err.Error()
		return c.JSON(200, retData)
	}
	req, err := http.NewRequest("POST", WechatUploadMediaAPI, bodyBuf)
	req.Header.Add("Content-Type", bodyWriter.FormDataContentType())
	urlQuery := req.URL.Query()
	if err != nil {
		retData.RetCode = "501"
		retData.RetMsg = err.Error()
		return c.JSON(200, retData)
	}
	token, found := TokenCache.Get("token")
	if !found {
		log.Printf("token获取失败!")
		retData.RetCode = "502"
		retData.RetMsg = "token获取失败!"
		return c.JSON(200, retData)
	}
	accessToken, ok := token.(AccessToken)
	if !ok {
		retData.RetCode = "502"
		retData.RetMsg = "token获取失败!"
		return c.JSON(200, retData)
	}
	urlQuery.Add("access_token", accessToken.AccessToken)
	urlQuery.Add("type", "image")
	req.URL.RawQuery = urlQuery.Encode()
	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	jsonbody, _ := ioutil.ReadAll(res.Body)
	media := MediaUpload{}
	err = json.Unmarshal(jsonbody, &media)
	if err != nil {
		retData.RetCode = "501"
		retData.RetMsg = err.Error()
		return c.JSON(200, retData)
	}
	if media.MediaID == "" {
		retData.RetCode = "503"
		retData.RetMsg = string("发送失败" + media.ErrMgs)
		return c.JSON(200, retData)
	}
	mediaid := media.MediaID
	err = SendMediaById(mediaid, toUser, "", "", "image", "")
	if err != nil {
		retData.RetCode = "503"
		retData.RetMsg = string("发送失败" + media.ErrMgs)
		return c.JSON(200, retData)
	}
	retData.RetCode = "200"
	retData.RetMsg = string("发送成功:" + mediaid)
	return c.JSON(200, retData)
}

func SendMediaById(mediaId string, touser string, toparty string, totag string, msgtype string, safe string) (err error) {
	image := MediaContent{}
	image.MediaId = mediaId

	msg := MediaPost{
		Image: image,
	}
	msg.ToUser = touser
	msg.AgentID = StringToInt(config.Weixin.AgentId)
	msg.MsgType = msgtype

	token, found := TokenCache.Get("token")
	if !found {
		log.Printf("token获取失败!")
		return err
	}
	accessToken, ok := token.(AccessToken)
	if !ok {
		err = errors.New("token获取失败!")
	}

	url := "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=" + accessToken.AccessToken
	jsonBody, err := encodeJson(msg)
	if err != nil {
		err = errors.New("token获取失败!")
	}
	result, err := WxPost(url, jsonBody)
	if err != nil {
		log.Printf("请求微信失败: %v", err)
	}
	log.Printf("发送信息给%s, 信息内容: %s, 微信返回结果: %v", touser, mediaId, result)

	return
}
func GetUserInfo(c echo.Context) error {
	retData := RetData{}
	//workno := c.Param("workno")
	workno := c.QueryParam("workno")
	if workno == "" {
		log.Printf("不存在工号!")
		retData.RetCode = "502"
		retData.RetMsg = "不存在!"
		return c.JSON(200, retData)
	}
	token, found := TokenCache.Get("token")

	if !found {
		log.Printf("token获取失败!")
		retData.RetCode = "502"
		retData.RetMsg = "token获取失败!"
		return c.JSON(200, retData)
	}
	accessToken, ok := token.(AccessToken)
	if !ok {
		retData.RetCode = "502"
		retData.RetMsg = "token获取失败!"
		return c.JSON(200, retData)
	}

	url := "https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=" + accessToken.AccessToken + "&userid=" + workno
	result, err := WxGet(url)
	if err != nil {
		log.Printf("请求微信失败: %v", err)
	}
	log.Printf("获取信息%s, 微信返回结果: %v", workno, result)
	return c.String(200, string(result))
}

//开启回调模式验证
func WxAuth(context echo.Context) error {

	echostr := context.FormValue("echostr")
	if echostr == "" {
		return errors.New("无法获取请求参数, echostr 为空")
	}

	wByte, err := base64.StdEncoding.DecodeString(echostr)
	if err != nil {
		return errors.New("接受微信请求参数 echostr base64解码失败(" + err.Error() + ")")
	}
	key, err := base64.StdEncoding.DecodeString(config.Weixin.EncodingAESKey + "=")
	if err != nil {
		return errors.New("配置 EncodingAESKey base64解码失败(" + err.Error() + "), 请检查配置文件内 EncodingAESKey 是否和微信后台提供一致")
	}

	keyByte := []byte(key)
	x, err := AesDecrypt(wByte, keyByte)
	if err != nil {
		return errors.New("aes 解码失败(" + err.Error() + "), 请检查配置文件内 EncodingAESKey 是否和微信后台提供一致")
	}

	buf := bytes.NewBuffer(x[16:20])
	var length int32
	binary.Read(buf, binary.BigEndian, &length)

	//验证返回数据ID是否正确
	appIDstart := 20 + length
	if len(x) < int(appIDstart) {
		return errors.New("获取数据错误, 请检查 EncodingAESKey 配置")
	}
	id := x[appIDstart : int(appIDstart)+len(config.Weixin.CorpID)]
	if string(id) == config.Weixin.CorpID {
		return context.JSONBlob(200, x[20:20+length])
	}
	return errors.New("微信验证appID错误, 微信请求值: " + string(id) + ", 配置文件内配置为: " + config.Weixin.CorpID)
}

type AccessToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}

//从微信获取 AccessToken
func GetAccessTokenFromWeixin() {

	for {
		if config.Weixin.CorpID == "" || config.Weixin.Secret == "" {
			log.Printf("corpId或者secret 获取失败, 请检查配置文件")
			return
		}

		WxAccessTokenUrl := "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=" + config.Weixin.CorpID + "&corpsecret=" + config.Weixin.Secret

		tr := &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			DisableCompression: true,
		}
		client := &http.Client{Transport: tr}
		result, err := client.Get(WxAccessTokenUrl)
		if err != nil {
			log.Printf("获取微信 Token 返回数据错误: %v, 10秒后重试!", err)
			time.Sleep(10 * time.Second)
			continue
		}

		res, err := ioutil.ReadAll(result.Body)

		if err != nil {
			log.Printf("获取微信 Token 返回数据错误: %v, 10秒后重试!", err)
			time.Sleep(10 * time.Second)
			continue
		}
		newAccess := AccessToken{}
		err = json.Unmarshal(res, &newAccess)
		if err != nil {
			log.Printf("获取微信 Token 返回数据解析 Json 错误: %v, 10秒后重试!", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if newAccess.ExpiresIn == 0 || newAccess.AccessToken == "" {
			log.Printf("获取微信错误代码: %v, 错误信息: %v, 10秒后重试!", newAccess.ErrCode, newAccess.ErrMsg)
			time.Sleep(10 * time.Second)
			continue
		}

		//延迟时间
		TokenCache.Set("token", newAccess, time.Duration(newAccess.ExpiresIn)*time.Second)
		log.Printf("微信 Token 更新成功: %s,有效时间: %v", newAccess.AccessToken, newAccess.ExpiresIn)
		time.Sleep(time.Duration(newAccess.ExpiresIn-1000) * time.Second)

	}

}

//微信请求数据
func WxPost(url string, jsonBody []byte) (string, error) {
	r, err := http.Post(url, "application/json;charset=utf-8", bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", err
	}

	return string(body), err
}
func WxGet(url string) (string, error) {
	r, err := http.Get(url)
	if err != nil {
		return "", err
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", err
	}

	return string(body), err
}

//获取当前运行路径
func GetWorkPath() string {
	if file, err := exec.LookPath(os.Args[0]); err == nil {
		return filepath.Dir(file) + "/"
	}
	return "./"
}

//AES解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("aes解密失败: %v", err)
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//string 类型转 int
func StringToInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		log.Printf("agent 类型转换失败, 请检查配置文件中 agentid 配置是否为纯数字(%v)", err)
		return 0
	}
	return n
}

//json序列化(禁止 html 符号转义)
func encodeJson(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
