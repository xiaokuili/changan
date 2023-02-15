/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca/src/models/db"
)

func InsertAppInfo(ac *db.AppInfo) error {
	if err := db.DB.Create(ac).Error; err != nil {
		return fmt.Errorf("[Gorm] create access control's app info failed: %s", err.Error())
	}
	return nil
}

func FindAppInfo(appId string) (*db.AppInfo, error) {
	var appInfo db.AppInfo
	if err := db.DB.Model(&db.AppInfo{}).Where("app_id = ?", appId).First(&appInfo).Error; err != nil {
		return nil, fmt.Errorf("[Gorm] find app info by app id failed: %s", err.Error())
	}
	return &appInfo, nil
}
