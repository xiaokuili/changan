/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handlers

type GenCertByCsrReq struct {
	OrgId     string `json:"orgId"`
	UserId    string `json:"userId"`
	UserType  string `json:"userType"`
	CertUsage string `json:"certUsage"`
	Csr       string `json:"csr"`
	Token     string `json:"token"`
}

type GenCertReq struct {
	OrgId         string `json:"orgId"`
	UserId        string `json:"userId"`
	UserType      string `json:"userType"`
	CertUsage     string `json:"certUsage"`
	PrivateKeyPwd string `json:"privateKeyPwd"`
	Country       string `json:"country"`
	Locality      string `json:"locality"`
	Province      string `json:"province"`
	Token         string `json:"token"`
}

type QueryCertReq struct {
	CertSn    int64  `json:"certSn"`
	OrgId     string `json:"orgId"`
	UserId    string `json:"userId"`
	UserType  string `json:"userType"`
	CertUsage string `json:"certUsage"`
	Token     string `json:"token"`
}

type RenewCertReq struct {
	CertSn int64  `json:"certSn"`
	Token  string `json:"token"`
}

type RevokeCertReq struct {
	RevokedCertSn int64  `json:"revokedCertSn"`
	IssuerCertSn  int64  `json:"issuerCertSn"`
	Reason        string `json:"reason"`
	Token         string `json:"token"`
}

type GenCrlReq struct {
	IssuerCertSn int64  `json:"issuerCertSn"`
	Token        string `json:"token"`
}

type GenCsrReq struct {
	OrgId         string `json:"orgId"`
	UserId        string `json:"userId"`
	UserType      string `json:"userType"`
	PrivateKeyPwd string `json:"privateKeyPwd"`
	Country       string `json:"country"`
	Locality      string `json:"locality"`
	Province      string `json:"province"`
	Token         string `json:"token"`
}

type LoginReq struct {
	AppId  string `json:"appId"`
	AppKey string `json:"appKey"`
	Token  string `json:"token"`
}

type TokenReq struct {
	Token string `json:"token"`
}

type GetNodeIdReq struct {
	OrgId     string `json:"orgId"`
	UserId    string `json:"userId"`
	UserType  string `json:"userType"`
	CertUsage string `json:"certUsage"`
	CertSn    int64  `json:"certSn"`
	Token     string `json:"token"`
}
