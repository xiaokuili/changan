/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"chainmaker.org/chainmaker-ca/src/loggers"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var allConf *AllConfig
var logger *zap.Logger

type AllConfig struct {
	LogConf             *loggers.LogConifg   `mapstructure:"log_config"`
	DBConf              *DBConfig            `mapstructure:"db_config"`
	BaseConf            *BaseConf            `mapstructure:"base_config"`
	RootCaConf          *CaConfig            `mapstructure:"root_config"`
	IntermediateCaConfs []*ImCaConfig        `mapstructure:"intermediate_config"`
	AccessControlConfs  []*AccessControlConf `mapstructure:"access_control_config"`
	Pkcs11Conf          *Pkcs11Conf          `mapstructure:"pkcs11_config"`
}

type BaseConf struct {
	ServerPort  string `mapstructure:"server_port"`
	CaType      string `mapstructure:"ca_type"`
	ExpireYear  int    `mapstructure:"expire_year"`
	ExpireMonth int    `mapstructure:"expire_month"`
	// For test
	CertValidTime     time.Duration `mapstructure:"cert_valid_time"`
	HashType          string        `mapstructure:"hash_type"`
	KeyType           string        `mapstructure:"key_type"`
	CanIssueca        bool          `mapstructure:"can_issue_ca"`
	ProvideServiceFor []string      `mapstructure:"provide_service_for"`
	IsKeyEncrypt      bool          `mapstructure:"key_encrypt"`
	AccessControl     bool          `mapstructure:"access_control"`
	DefaultDomain     string        `mapstructure:"default_domain"`
}

type CaConfig struct {
	CsrConf  *CsrConf    `mapstructure:"csr"`
	CertConf []*CertConf `mapstructure:"cert"`
}

type ImCaConfig struct {
	CsrConf *CsrConf `mapstructure:"csr"`
	KeyId   string   `mapstructure:"key_id"`
}

type CsrConf struct {
	CN       string `mapstructure:"CN"`
	O        string `mapstructure:"O"`
	OU       string `mapstructure:"OU"`
	Country  string `mapstructure:"country"`
	Locality string `mapstructure:"locality"`
	Province string `mapstructure:"province"`
}

type CertConf struct {
	CertType       string `mapstructure:"cert_type"`
	CertPath       string `mapstructure:"cert_path"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
	KeyId          string `mapstructure:"key_id"`
}

type AccessControlConf struct {
	AppRole string `mapstructure:"app_role"`
	AppId   string `mapstructure:"app_id"`
	AppKey  string `mapstructure:"app_key"`
}

type Pkcs11Conf struct {
	Enabled          bool   `mapstructure:"enabled"`
	Library          string `mapstructure:"library"`
	Label            string `mapstructure:"label"`
	Password         string `mapstructure:"password"`
	SessionCacheSize int    `mapstructure:"session_cache_size"`
	Hash             string `mapstructure:"hash"`
}

// GetConfigEnv --Specify the path and name of the configuration file (Env)
func GetConfigEnv() string {
	var env string
	n := len(os.Args)
	for i := 1; i < n-1; i++ {
		if os.Args[i] == "-e" || os.Args[i] == "--env" {
			env = os.Args[i+1]
			break
		}
	}
	fmt.Println("[env]:", env)
	if env == "" {
		fmt.Println("env is empty, set default")
		env = ""
	}
	return env
}

//GetFlagPath --Specify the path and name of the configuration file (flag)
func GetFlagPath() string {
	var configPath string
	flag.StringVar(&configPath, "config", "./conf/config.yaml", "please input config file path")
	flag.Parse()
	return configPath
}

//SetConfig --Set config path and file name
func SetConfig(envPath string) {
	var configPath string
	if envPath != "" {
		configPath = envPath
	} else {
		configPath = GetFlagPath()
	}
	InitConfig(configPath)
}

//InitConfig --init config
func InitConfig(configPath string) {
	viper.SetConfigFile(configPath)
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
	allConf, err = GetAllConf()
	if err != nil {
		panic(err)
	}
	err = loggers.InitLogger(allConf.GetLogConf())
	if err != nil {
		panic(err)
	}
	logger = loggers.GetLogger()
	logger.Info("init config successful", zap.Any("allconfig", allConf))
}

//DBConfig /
type DBConfig struct {
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	IP       string `mapstructure:"ip"`
	Port     string `mapstructure:"port"`
	DbName   string `mapstructure:"dbname"`
}

//GetDBConfig --Get DB config from config file.
func GetDBConfig() string {
	dbConfig := allConf.GetDBConf()
	mysqlURL := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=%s&parseTime=True&loc=Local",
		dbConfig.User, dbConfig.Password, dbConfig.IP, dbConfig.Port, dbConfig.DbName, "utf8")
	return mysqlURL
}

//Get all conf
func GetAllConf() (*AllConfig, error) {
	var allConf AllConfig
	err := viper.Unmarshal(&allConf)
	if err != nil {
		return nil, fmt.Errorf("get all config failed: %s", err.Error())
	}
	if allConf.DBConf == nil {
		return nil, fmt.Errorf("get all config failed: not found db config")
	}
	if allConf.BaseConf == nil {
		return nil, fmt.Errorf("get all config failed: not found base config")
	}
	if allConf.RootCaConf == nil {
		return nil, fmt.Errorf("get all config failed: not found root config")
	}
	if allConf.RootCaConf.CertConf == nil {
		return nil, fmt.Errorf("get all config failed: not found root cert config")
	}
	// if allConf.Pkcs11Conf == nil {
	// 	return nil, fmt.Errorf("get all config failed: not found pkcs11 config")
	// }
	return &allConf, nil
}

func GetAllConfig() *AllConfig {
	return allConf
}

func (ac *AllConfig) GetServerPort() string {
	return ac.BaseConf.ServerPort
}

func (ac *AllConfig) GetHashType() string {
	return strings.ToUpper(ac.BaseConf.HashType)
}

func (ac *AllConfig) GetKeyType() string {
	return strings.ToUpper(ac.BaseConf.KeyType)
}

func (ac *AllConfig) GetDefaultExpireYear() int {
	return ac.BaseConf.ExpireYear
}

func (ac *AllConfig) GetDefaultExpireMonth() int {
	return ac.BaseConf.ExpireMonth
}

func (ac *AllConfig) GetDefaultCertValidTime() time.Duration {
	return ac.BaseConf.CertValidTime
}

func (ac *AllConfig) GetCanIssueCa() bool {
	return ac.BaseConf.CanIssueca
}

func (ac *AllConfig) GetProvideServiceFor() []string {
	return ac.BaseConf.ProvideServiceFor
}

func (ac *AllConfig) IsKeyEncrypt() bool {
	return ac.BaseConf.IsKeyEncrypt
}

func (ac *AllConfig) IsAccessControl() bool {
	return ac.BaseConf.AccessControl
}

func (ac *AllConfig) GetCaType() string {
	return strings.ToLower(ac.BaseConf.CaType)
}

func (ac *AllConfig) GetRootConf() *CaConfig {
	return ac.RootCaConf
}

func (ac *AllConfig) GetRootCsrConf() *CsrConf {
	return ac.RootCaConf.CsrConf
}

func (ac *AllConfig) GetRootCertConf() []*CertConf {
	return ac.RootCaConf.CertConf
}

func (ac *AllConfig) GetBaseConf() *BaseConf {
	return ac.BaseConf
}

func (ac *AllConfig) GetIntermediateConf() []*ImCaConfig {
	return ac.IntermediateCaConfs
}

func (ac *AllConfig) GetLogConf() *loggers.LogConifg {
	return ac.LogConf
}

func (ac *AllConfig) GetDBConf() *DBConfig {
	return ac.DBConf
}

func (ac *AllConfig) GetAccessControlConf() []*AccessControlConf {
	return ac.AccessControlConfs
}

func (ac *AllConfig) GetPkcs11Conf() *Pkcs11Conf {
	return ac.Pkcs11Conf
}

func (ac *AllConfig) GetPkcs11Enabled() bool {
	return ac.Pkcs11Conf.Enabled
}

func (ac *AllConfig) GetDefaultDomain() string {
	return ac.BaseConf.DefaultDomain
}
