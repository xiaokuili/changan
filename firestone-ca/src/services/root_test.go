/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"log"
	"testing"

	"chainmaker.org/chainmaker-ca/src/models/db"
	"chainmaker.org/chainmaker-ca/src/utils"
)

const (
	configPath  = "../conf/config.yaml"
	keyTypeStr  = "SM2"
	hashTypeStr = "SM3"
	keyPath     = "./testdata/rootca/root.key"
	certPath    = "./testdata/rootca/root.crt"
)

func TestInit(t *testing.T) {
	utils.SetConfig(configPath)
	db.GormInit()
	allConfig = utils.GetAllConfig()
	InitServer()
}

func TestGenRootCa(t *testing.T) {
	TestInit(t)
	rootCsrConf := &utils.CsrConf{
		CN:       "test.com",
		O:        "test",
		OU:       "root",
		Country:  "test.country",
		Locality: "test.locality",
		Province: "test.province",
	}
	err := genRootCa(rootCsrConf, keyTypeStr, hashTypeStr, db.SIGN, keyPath, certPath, NO_PKCS11_KEY_ID)
	if err != nil {
		log.Fatalf("gen root ca failed: %s", err.Error())
	}
}

func TestLoadRootCaFromConfig(t *testing.T) {
	TestInit(t)
	keyPath := "./testdata/rootca/root.key"
	certPath := "./testdata/rootca/root.crt"
	err := loadRootCaFromConfig(certPath, keyPath, db.SIGN)
	if err != nil {
		log.Fatalf("load root ca failed: %s", err.Error())
	}
}

func TestCreateRootCa(t *testing.T) {
	TestInit(t)
	err := CreateRootCa()
	if err != nil {
		log.Fatalf("create root ca failed: %s", err.Error())
	}
}
