/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca/src/models/db"
)

//Find certcontent by Sn
func FindCertContentBySn(sn int64) (*db.CertContent, error) {
	var certContent db.CertContent
	if err := db.DB.Where("serial_number=?", sn).First(&certContent).Error; err != nil {
		return nil, fmt.Errorf("[Gorm] find cert content by sn error: %s, sn: %d", err.Error(), sn)
	}
	return &certContent, nil
}

//Update cert content
func UpdateCertContent(oldCertContent, newCertContent *db.CertContent) error {
	if err := db.DB.Model(oldCertContent).
		Select("content", "cert_raw", "key_usage", "ext_key_usage", "is_ca", "issue_date", "expiration_date").
		Updates(newCertContent).Error; err != nil {
		return fmt.Errorf("[Gorm] update cert content failed: %s, oldCert: %v, newCert: %v",
			err.Error(), oldCertContent, newCertContent)
	}
	return nil
}
