/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"fmt"
	"testing"
)

const ConfigPath = "../conf/config.yaml"

func TestInitConf(t *testing.T) {
	SetConfig(ConfigPath)
}

func TestGetAllConf(t *testing.T) {
	TestInitConf(t)
	allConf := GetAllConfig()
	fmt.Printf("all config: %+v\n", allConf)
	fmt.Printf("Log config: %+v\n", allConf.GetLogConf())
	fmt.Printf("DB config: %+v\n", allConf.GetDBConf())
	fmt.Printf("Base config: %+v\n", allConf.GetBaseConf())
	fmt.Printf("Root ca config: %+v\n", allConf.GetRootConf())
	timed := allConf.GetDefaultCertValidTime()
	fmt.Printf("test cert valid config: %+v \n", timed)
}
