/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"encoding/pem"
	"fmt"
	"log"
	"testing"

	"chainmaker.org/chainmaker-ca/src/models/db"
)

const (
	OrgId                  = "TestOrg1"
	UserId                 = "TestUser"
	UserType  db.UserType  = db.USER_ADMIN
	CertUsage db.CertUsage = db.TLS
	Country                = "CN"
	Locality               = "Beijing"
	Province               = "Beijing"
)

func TestGenCert(t *testing.T) {
	TestInit(t)
	req := &GenCertReq{
		OrgId:     OrgId,
		UserId:    UserId,
		UserType:  UserType,
		CertUsage: CertUsage,
		Country:   Country,
		Locality:  Locality,
		Province:  Province,
	}
	certAndPirvateKey, err := GenCert(req)
	if err != nil {
		log.Fatalf("gen cert failed: %s", err.Error())
	}
	fmt.Printf("cert content: %s\n", certAndPirvateKey.CertContent)
	fmt.Printf("private key: %s\n", certAndPirvateKey.PrivateKey)
}

func TestGenCsr(t *testing.T) {
	TestInit(t)
	req := &GenCsrReq{
		OrgId:    OrgId,
		UserId:   UserId,
		UserType: UserType,
		Country:  Country,
		Locality: Locality,
		Province: Province,
	}
	csrBytes, err := GenCsr(req)
	if err != nil {
		log.Fatalf("gen csr failed: %s", err.Error())
	}
	fmt.Println(string(csrBytes))
}

func TestGenCertByCsr(t *testing.T) {
	TestInit(t)
	req := &GenCsrReq{
		OrgId:    OrgId,
		UserId:   UserId,
		UserType: UserType,
		Country:  Country,
		Locality: Locality,
		Province: Province,
	}
	csrBytes, err := GenCsr(req)
	if err != nil {
		log.Fatalf("gen csr failed: %s", err.Error())
	}
	csrReq := &GenCertByCsrReq{
		OrgId:     OrgId,
		UserId:    UserId,
		UserType:  UserType,
		CertUsage: CertUsage,
		CsrBytes:  csrBytes,
	}
	certContent, err := GenCertByCsr(csrReq)
	if err != nil {
		log.Fatalf("gen csr failed: %s", err.Error())
	}
	fmt.Println(certContent)
}

func TestQueryCerts(t *testing.T) {
	TestInit(t)
	queryReq := &QueryCertsReq{
		//OrgId:     OrgId,
		//UserId: UserId,
		//UserType: db.UserType2NameMap[UserType],
		CertUsage: db.CertUsage2NameMap[CertUsage],
	}
	resp, err := QueryCerts(queryReq)
	if err != nil {
		log.Fatalf("query certs failed: %s", err.Error())
	}
	for _, v := range resp {
		fmt.Printf("cert info: %+v\n", v)
	}
}

func TestRenewCert(t *testing.T) {
	TestInit(t)
	queryReq := &QueryCertsReq{
		OrgId:     OrgId,
		UserId:    UserId,
		UserType:  db.UserType2NameMap[UserType],
		CertUsage: db.CertUsage2NameMap[CertUsage],
	}
	resp, _ := QueryCerts(queryReq)
	req := &RenewCertReq{
		CertSn: resp[0].CertSn,
	}
	cert, err := RenewCert(req)
	if err != nil {
		log.Fatalf("renew cert failed: %s", err.Error())
	}
	fmt.Printf("cert: %s", cert)
}

func TestRevokeCert(t *testing.T) {
	TestInit(t)
	queryReq := &QueryCertsReq{
		OrgId:     OrgId,
		UserId:    UserId,
		UserType:  db.UserType2NameMap[UserType],
		CertUsage: db.CertUsage2NameMap[CertUsage],
	}
	resp, _ := QueryCerts(queryReq)
	req := &RevokeCertReq{
		RevokedCertSn: resp[0].CertSn,
		IssuerCertSn:  resp[0].IssuerSn,
	}
	crl, err := RevokeCert(req)
	if err != nil {
		log.Fatalf("revoke cert failed: %s", err.Error())
	}
	crlBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})
	fmt.Println("crl: " + string(crlBytes))
}

func TestGenCrl(t *testing.T) {
	TestInit(t)
	queryReq := &QueryCertsReq{
		OrgId:     OrgId,
		UserId:    UserId,
		UserType:  db.UserType2NameMap[UserType],
		CertUsage: db.CertUsage2NameMap[CertUsage],
	}
	resp, _ := QueryCerts(queryReq)
	req := &GenCrlReq{
		IssuerCertSn: resp[0].IssuerSn,
	}
	crl, err := GenCrl(req)
	if err != nil {
		log.Fatalf("generate crl failed: %s", err.Error())
	}
	crlBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})
	fmt.Println("crl: " + string(crlBytes))
}
