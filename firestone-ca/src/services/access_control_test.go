/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"fmt"
	"testing"
)

func TestGetAppToken(t *testing.T) {
	TestInit(t)
	appId := "admin"
	appKey := "passw0rd"
	token, err := GetAppToken(appId, appKey)
	if err != nil {
		fmt.Printf("get token failed: %s\n", err.Error())
	}
	fmt.Printf("token: %s\n", token)

	claims, err := ParseToken(token)
	if err != nil {
		fmt.Printf("parse token failed: %s\n", err.Error())
		return
	}
	fmt.Printf("appId: %s\n", claims.AppId)
	fmt.Printf("appRole: %d\n", claims.AppRole)
}
