/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca/src/models/db"
)

//Find keypair by ski
func FindKeyPairBySki(ski string) (*db.KeyPair, error) {
	var keyPair db.KeyPair
	if err := db.DB.Where("ski=?", ski).First(&keyPair).Error; err != nil {
		return nil, fmt.Errorf("[Gorm] get key pair by ski failed: %s, ski: %s", err.Error(), ski)
	}
	return &keyPair, nil
}
