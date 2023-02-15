/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"fmt"

	"chainmaker.org/chainmaker-ca/src/models/db"
)

//Find certcontent which certstatus is active by conditions
func FindCertContent(userId, orgId string, usage db.CertUsage, userType db.UserType) (*db.CertContent, error) {
	certInfo, err := FindCertInfo(userId, orgId, usage, userType)
	if err != nil {
		return nil, fmt.Errorf("find cert content failed: %s", err.Error())
	}
	certSn := certInfo.SerialNumber
	certContent, err := FindCertContentBySn(certSn)
	if err != nil {
		return nil, fmt.Errorf("find cert content failed: %s", err.Error())
	}
	return certContent, nil
}

//Find certcontent which certstatus is active by conditions
func FindKeyPair(userId, orgId string, usage db.CertUsage, userType db.UserType) (*db.KeyPair, error) {
	certInfo, err := FindCertInfo(userId, orgId, usage, userType)
	if err != nil {
		return nil, fmt.Errorf("find key pair failed: %s", err.Error())
	}
	keyPairSki := certInfo.PrivateKeyId
	keyPair, err := FindKeyPairBySki(keyPairSki)
	if err != nil {
		return nil, fmt.Errorf("find key pair failed: %s", err.Error())
	}
	return keyPair, nil
}

//Find certcontent by conditions
func FindCertContents(userId, orgId string, usage db.CertUsage, userType db.UserType) ([]*db.CertContent, error) {
	certInfoList, err := FindCertInfos(userId, orgId, usage, userType)
	if err != nil {
		return nil, fmt.Errorf("find cert contents failed: %s", err.Error())
	}
	var res []*db.CertContent
	for _, value := range certInfoList {
		tmp, err := FindCertContentBySn(value.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("find cert contents failed: %s", err.Error())
		}
		res = append(res, tmp)
	}
	return res, nil
}
