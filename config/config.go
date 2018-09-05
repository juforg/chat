package config

import (
	"github.com/labstack/gommon/log"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type Conf struct {
	Http struct {
		Port string
	}
	Weixin struct {
		CorpID         string
		AgentId        string
		Secret         string
		EncodingAESKey string
	}
}

func (c *Conf) GetConf() *Conf {
	yamlFile, err := ioutil.ReadFile("conf.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return c
}
