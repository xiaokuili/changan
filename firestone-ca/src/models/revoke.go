/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca/src/models/db"
)

//Inset revokedcert into database
func InsertRevokedCert(revokedCert *db.RevokedCert) error {
	if err := db.DB.Create(revokedCert).Error; err != nil {
		return fmt.Errorf("[Gorm] create revoked cert info failed: %s", err.Error())
	}
	return nil
}

//Query revokedcert by issue sn
func QueryRevokedCertByIssueSn(sn int64) ([]*db.RevokedCert, error) {
	var revokedCerts []*db.RevokedCert
	err := db.DB.Model(&db.RevokedCert{}).Where("revoked_by=?", sn).Find(&revokedCerts).Error
	if err != nil {
		return nil, fmt.Errorf("[Gorm] query revoked cert by issuer sn failed: %s", err.Error())
	}
	return revokedCerts, nil
}

//Query revokedcert by revoke sn
func QueryRevokedCertByRevokedSn(sn int64) (*db.RevokedCert, error) {
	var revokedCert db.RevokedCert
	err := db.DB.Model(&db.RevokedCert{}).Where("revoked_cert_sn=?", sn).First(&revokedCert).Error
	if err != nil {
		return nil, fmt.Errorf("[Gorm] query revoked cert by revoked sn failed: %s", err.Error())
	}
	return &revokedCert, nil
}
