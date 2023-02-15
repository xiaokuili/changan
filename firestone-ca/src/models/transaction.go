/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca/src/models/db"
	"gorm.io/gorm"
)

//The transaction that inserts cert, kepair, and certinfo into the database
func CreateCertTransaction(certContent *db.CertContent, certInfo *db.CertInfo, keyPair *db.KeyPair) error {
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(keyPair).Error; err != nil {
			return fmt.Errorf("[Gorm] create key pair to db failed: %s", err.Error())
		}
		if err := tx.Create(certContent).Error; err != nil {
			return fmt.Errorf("[Gorm] create cert content to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
		}
		if err := tx.Create(certInfo).Error; err != nil {
			return fmt.Errorf("[Gorm] create cert info to db failed: %s, sn: %d", err.Error(), certInfo.SerialNumber)
		}
		return nil
	})
	return err
}

//The transaction that inserts cert and certinfo into the database
func CreateCertAndInfoTransaction(certContent *db.CertContent, certInfo *db.CertInfo) error {
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(certContent).Error; err != nil {
			return fmt.Errorf("[Gorm] create cert content to db failed: %s, sn: %d", err.Error(), certContent.SerialNumber)
		}
		if err := tx.Create(certInfo).Error; err != nil {
			return fmt.Errorf("[Gorm] create cert info to db failed: %s, sn: %d", err.Error(), certInfo.SerialNumber)
		}
		return nil
	})
	return err
}
