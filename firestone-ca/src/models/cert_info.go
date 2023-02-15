/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca/src/models/db"
)

//Find certinfo by sn
func FindCertInfoBySn(sn int64) (*db.CertInfo, error) {
	var certInfo db.CertInfo
	if err := db.DB.Where("serial_number=?", sn).First(&certInfo).Error; err != nil {
		return nil, fmt.Errorf("[Gorm] find cert infos by sn error: %s, sn: %d", err.Error(), sn)
	}
	return &certInfo, nil
}

//Find certinfo by privateKeyid
func FindCertInfoByPrivateKey(privateKeyId string) (*db.CertInfo, error) {
	var certInfo db.CertInfo
	if err := db.DB.Where("private_key_id=?", privateKeyId).First(&certInfo).Error; err != nil {
		return nil, fmt.Errorf("[Gorm] find cert info by private key id failed: %s, private key id: %s",
			err.Error(), privateKeyId)
	}
	return &certInfo, nil
}

//Find certinfo by conditions
func FindCertInfo(userId, orgId string, usage db.CertUsage, userType db.UserType) (*db.CertInfo, error) {
	var certInfo db.CertInfo
	tx := db.DB
	if userId != "" {
		tx = tx.Where("user_id=?", userId)
	}
	if orgId != "" {
		tx = tx.Where("org_id=?", orgId)
	}
	if userType != 0 {
		tx = tx.Where("user_type =?", userType)
	}
	if usage != 0 {
		tx = tx.Where("cert_usage=?", usage)
	}
	err := tx.First(&certInfo).Error
	if err != nil {
		return nil, fmt.Errorf("[Gorm] find cert info by conditions failed: %s", err.Error())
	}
	return &certInfo, nil
}

//Find certinfos by conditions
func FindCertInfos(userId, orgId string, usage db.CertUsage, userType db.UserType) ([]*db.CertInfo, error) {
	var certInfos []*db.CertInfo
	tx := db.DB
	if userId != "" {
		tx = tx.Where("user_id=?", userId)
	}
	if orgId != "" {
		tx = tx.Where("org_id=?", orgId)
	}
	if userType != 0 {
		tx = tx.Where("user_type =?", userType)
	}
	if usage != 0 {
		tx = tx.Where("cert_usage=?", usage)
	}
	err := tx.Find(&certInfos).Error
	if err != nil {
		return nil, fmt.Errorf("[Gorm] find cert infos by conditions failed: %s", err.Error())
	}
	return certInfos, nil
}

// type result struct {
// 	nodeId string `gorm:"column:p2p_node_id"`
// }

func FindNodeIdByCertSn(certSn int64) (string, error) {
	var nodeId string
	if err := db.DB.Table(db.CERT_INFO_NAME).
		Select("p2p_node_id").Where("serial_number=?", certSn).
		Scan(&nodeId).Error; err != nil {
		return nodeId, fmt.Errorf("[Gorm] find node id by cert sn failed: %s, cert sn: %d",
			err.Error(), certSn)
	}
	return nodeId, nil
}

func FindNodeIdByKeyId(keyId string) (string, error) {
	var nodeId string
	if err := db.DB.Table(db.CERT_INFO_NAME).
		Select("p2p_node_id").Where("private_key_id=?", keyId).
		Scan(&nodeId).Error; err != nil {
		return nodeId, fmt.Errorf("[Gorm] find node id by key id failed: %s, key id: %s",
			err.Error(), keyId)
	}
	return nodeId, nil
}
