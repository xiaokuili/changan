/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"chainmaker.org/chainmaker/common/v2/crypto"
)

const (
	//CERT_CONTENT_NAME table name
	CERT_CONTENT_NAME = "cert_content"
	//CERT_INFO_NAME table name
	CERT_INFO_NAME = "cert_info"
	//KEY_PAIR_NAME table name
	KEY_PAIR_NAME = "key_pair"
	//REVOKED_CERT_NAME table name
	REVOKED_CERT_NAME = "revoked_cert"
	//ACCESS_CONTROL table name
	ACCESS_CONTROL = "app_info"
)

type TableModel struct {
	Id        int `gorm:"primaryKey;autoIncrement"`
	CreatedAt int
	UpdatedAt int
}

//CertContent The initiatively populated field in the program & the final generated certificate file
type CertContent struct {
	TableModel
	SerialNumber       int64  `gorm:"uniqueIndex"`
	Content            string `gorm:"type:longtext"`
	Signature          string `gorm:"type:longtext"`
	Country            string
	Locality           string
	Province           string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	Ski                string
	Aki                string
	KeyUsage           int
	ExtKeyUsage        string
	CsrContent         string `gorm:"type:longtext"`
	IsCa               bool
	IssueDate          int64
	ExpirationDate     int64
}

//CertInfo Other relevant information
type CertInfo struct {
	TableModel
	SerialNumber int64
	PrivateKeyId string
	IssuerSn     int64
	P2pNodeId    string
	OrgId        string    `gorm:"index: orgid_usertype_certusage_userid_index,unique"`
	UserType     UserType  `gorm:"index: orgid_usertype_certusage_userid_index,unique"`
	CertUsage    CertUsage `gorm:"index: orgid_usertype_certusage_userid_index,unique"`
	UserId       string    `gorm:"index: orgid_usertype_certusage_userid_index,unique"`
}

//KeyPair public/private key pair informations
type KeyPair struct {
	TableModel
	Ski        string `gorm:"uniqueIndex"`
	PrivateKey string `gorm:"type:longtext"`
	PublicKey  string `gorm:"type:longtext"`
	HashType   crypto.HashType
	KeyType    crypto.KeyType
}

//RevokedCert revoked cert
type RevokedCert struct {
	TableModel
	RevokedCertSN    int64 `gorm:"uniqueIndex"`
	Reason           string
	RevokedStartTime int64
	RevokedEndTime   int64
	RevokedBy        int64
	OrgId            string
}

type AppInfo struct {
	TableModel
	AppId   string `gorm:"uniqueIndex"`
	AppKey  string
	AppRole AccessRole
}

//Table name function
func (*CertContent) TableName() string {
	return CERT_CONTENT_NAME
}

func (*CertInfo) TableName() string {
	return CERT_INFO_NAME
}

func (*KeyPair) TableName() string {
	return KEY_PAIR_NAME
}

func (*RevokedCert) TableName() string {
	return REVOKED_CERT_NAME
}

func (*AppInfo) TableName() string {
	return ACCESS_CONTROL
}
