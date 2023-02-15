/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"chainmaker.org/chainmaker-ca/src/models/db"
)

type GenCertByCsrReq struct {
	OrgId     string
	UserId    string
	UserType  db.UserType
	CertUsage db.CertUsage
	CsrBytes  []byte
}

type GenCertReq struct {
	OrgId         string
	UserId        string
	UserType      db.UserType
	CertUsage     db.CertUsage
	PrivateKeyPwd string
	Country       string
	Locality      string
	Province      string
}

type QueryCertsReq struct {
	CertSn    int64
	OrgId     string
	UserId    string
	UserType  string
	CertUsage string
}

type RenewCertReq struct {
	CertSn int64
}

type RevokeCertReq struct {
	RevokedCertSn int64
	IssuerCertSn  int64
	Reason        string
}

type GenCrlReq struct {
	IssuerCertSn int64
}

type GenCsrReq struct {
	OrgId         string
	UserId        string
	UserType      db.UserType
	PrivateKeyPwd string
	Country       string
	Locality      string
	Province      string
}

type CertInfos struct {
	UserId         string `json:"userId"`
	OrgId          string `json:"orgId"`
	UserType       string `json:"userType"`
	CertUsage      string `json:"certUsage"`
	CertSn         int64  `json:"certSn"`
	IssuerSn       int64  `json:"issuerSn"`
	CertContent    string `json:"certContent"`
	ExpirationDate int64  `json:"expirationDate"`
	IsRevoked      bool   `json:"isRevoked"`
}

type GetTLSCertNodeIdReq struct {
	OrgId     string
	UserId    string
	UserType  db.UserType
	CertUsage db.CertUsage
	CertSn    int64
}

type ApplyCertResp struct {
	CertSn      int64  `json:"certSn"`
	IssueCertSn int64  `json:"issueCertSn"`
	CertContent string `json:"cert"`
	PrivateKey  string `json:"privateKey,omitempty"`
}

type DynamToken struct {
	Key string `json:"key"`
}
