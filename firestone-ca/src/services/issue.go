/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-ca/src/models/db"
	"chainmaker.org/chainmaker/common/v2/cert"
	"chainmaker.org/chainmaker/common/v2/crypto"
	bcx509 "chainmaker.org/chainmaker/common/v2/crypto/x509"
	"github.com/tjfoc/gmsm/sm2"
)

type CSRRequestConfig struct {
	PrivateKey         crypto.PrivateKey
	Country            string
	Locality           string
	Province           string
	OrganizationalUnit string
	Organization       string
	CommonName         string
}

type CertRequestConfig struct {
	HashType         crypto.HashType
	IssuerPrivateKey crypto.PrivateKey
	CsrBytes         []byte
	IssuerCertBytes  []byte
	ValidTime        time.Duration
	CertUsage        db.CertUsage
	UserType         db.UserType
}

type GenCertRequestConfig struct {
	Country            []string
	Locality           []string
	Province           []string
	OrganizationalUnit []string
	Organization       []string
	Extension          []pkix.Extension
	ExtraExtensions    []pkix.Extension
	CommonName         string
	ValidTime          time.Duration
	CertUsage          db.CertUsage
	UserType           db.UserType
}

type RootCertRequestConfig struct {
	PrivateKey         crypto.PrivateKey
	Country            string
	Locality           string
	Province           string
	OrganizationalUnit string
	Organization       string
	CommonName         string
	ValidTime          time.Duration
	CertUsage          db.CertUsage
	UserType           db.UserType
	HashType           string
}

//Issue cert by self(root ca)
func IssueCertBySelf(rootCertConf *RootCertRequestConfig) (*db.CertContent, error) {
	genCertConf := &GenCertRequestConfig{
		Country:            []string{rootCertConf.Country},
		Locality:           []string{rootCertConf.Locality},
		Province:           []string{rootCertConf.Province},
		OrganizationalUnit: []string{rootCertConf.OrganizationalUnit},
		Organization:       []string{rootCertConf.Organization},
		CommonName:         rootCertConf.CommonName,
		ValidTime:          rootCertConf.ValidTime,
		CertUsage:          rootCertConf.CertUsage,
		UserType:           rootCertConf.UserType,
	}
	template, err := generateCertTemplate(genCertConf)
	if err != nil {
		return nil, err
	}
	template.SignatureAlgorithm = getSignatureAlgorithm(rootCertConf.PrivateKey)
	hashType, err := checkHashType(rootCertConf.HashType)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId, err = cert.ComputeSKI(hashType, rootCertConf.PrivateKey.PublicKey().ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("issue cert by self failed: %s", err.Error())
	}
	x509certEncode, err := bcx509.CreateCertificate(rand.Reader, template, template,
		rootCertConf.PrivateKey.PublicKey().ToStandardKey(), rootCertConf.PrivateKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("issue cert by self failed: %s", err.Error())
	}
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	extKeyUsageStr, err := ExtKeyUsageToString(template.ExtKeyUsage)
	if err != nil {
		return nil, err
	}
	certContent := &db.CertContent{
		SerialNumber:       template.SerialNumber.Int64(),
		Content:            string(certPemBytes),
		Signature:          hex.EncodeToString(template.Signature),
		Country:            template.Subject.Country[0],
		Locality:           template.Subject.Locality[0],
		Province:           template.Subject.Province[0],
		Organization:       template.Subject.Organization[0],
		OrganizationalUnit: template.Subject.OrganizationalUnit[0],
		CommonName:         template.Subject.CommonName,
		Ski:                hex.EncodeToString(template.SubjectKeyId),
		Aki:                hex.EncodeToString(template.AuthorityKeyId),
		KeyUsage:           int(template.KeyUsage),
		ExtKeyUsage:        extKeyUsageStr,
		IsCa:               template.IsCA,
		IssueDate:          template.NotBefore.Unix(),
		ExpirationDate:     template.NotAfter.Unix(),
	}
	return certContent, nil
}

//Issue certificate
func IssueCertificate(certConf *CertRequestConfig) (*db.CertContent, error) {
	issuerCert, err := ParseCertificate(certConf.IssuerCertBytes)
	if err != nil {
		return nil, err
	}
	csrOriginal, err := ParseCsr(certConf.CsrBytes)
	if err != nil {
		return nil, err
	}
	csr, err := bcx509.X509CertCsrToChainMakerCertCsr(csrOriginal)
	if err != nil {
		return nil, fmt.Errorf("issue cert failed: %s", err.Error())
	}

	if err = csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("issue cert failed: %s", err.Error())
	}
	genConf := &GenCertRequestConfig{
		Country:            csr.Subject.Country,
		Locality:           csr.Subject.Locality,
		Province:           csr.Subject.Province,
		OrganizationalUnit: csr.Subject.OrganizationalUnit,
		Organization:       csr.Subject.Organization,
		CommonName:         csr.Subject.CommonName,
		CertUsage:          certConf.CertUsage,
		UserType:           certConf.UserType,
		ValidTime:          certConf.ValidTime,
		Extension:          csr.Extensions,
		ExtraExtensions:    csr.ExtraExtensions,
	}
	template, err := generateCertTemplate(genConf)
	if err != nil {
		return nil, err
	}
	template.Signature = csr.Signature
	template.SignatureAlgorithm = x509.SignatureAlgorithm(csr.SignatureAlgorithm)
	template.PublicKey = csr.PublicKey
	template.PublicKeyAlgorithm = x509.PublicKeyAlgorithm(csr.PublicKeyAlgorithm)
	template.Issuer = issuerCert.Subject
	if issuerCert.SubjectKeyId != nil {
		template.AuthorityKeyId = issuerCert.SubjectKeyId
	} else {
		template.AuthorityKeyId, err = cert.ComputeSKI(certConf.HashType, issuerCert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("issue cert failed: %s", err.Error())
		}
	}

	template.SubjectKeyId, err = cert.ComputeSKI(certConf.HashType, csr.PublicKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("issue cert failed: %s", err.Error())
	}

	x509certEncode, err := bcx509.CreateCertificate(rand.Reader, template, issuerCert,
		csr.PublicKey.ToStandardKey(), certConf.IssuerPrivateKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("issue cert failed: %s", err.Error())
	}
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	extKeyUsageStr, err := ExtKeyUsageToString(template.ExtKeyUsage)
	if err != nil {
		return nil, err
	}
	certContent := &db.CertContent{
		SerialNumber:       template.SerialNumber.Int64(),
		Content:            string(certPemBytes),
		Signature:          hex.EncodeToString(template.Signature),
		Country:            template.Subject.Country[0],
		Locality:           template.Subject.Locality[0],
		Province:           template.Subject.Province[0],
		Organization:       template.Subject.Organization[0],
		OrganizationalUnit: template.Subject.OrganizationalUnit[0],
		CommonName:         template.Subject.CommonName,
		Ski:                hex.EncodeToString(template.SubjectKeyId),
		Aki:                hex.EncodeToString(template.AuthorityKeyId),
		KeyUsage:           int(template.KeyUsage),
		ExtKeyUsage:        extKeyUsageStr,
		CsrContent:         string(certConf.CsrBytes),
		IsCa:               template.IsCA,
		IssueDate:          template.NotBefore.Unix(),
		ExpirationDate:     template.NotAfter.Unix(),
	}
	return certContent, nil
}

func createCSR(csrConf *CSRRequestConfig) ([]byte, error) {

	signatureAlgorithm := getSignatureAlgorithm(csrConf.PrivateKey)

	templateX509 := &x509.CertificateRequest{
		SignatureAlgorithm: signatureAlgorithm,
		Subject: pkix.Name{
			Country:            []string{csrConf.Country},
			Locality:           []string{csrConf.Locality},
			Province:           []string{csrConf.Province},
			OrganizationalUnit: []string{csrConf.OrganizationalUnit},
			Organization:       []string{csrConf.Organization},
			CommonName:         csrConf.CommonName,
		},
	}
	template, err := bcx509.X509CertCsrToChainMakerCertCsr(templateX509)
	if err != nil {
		return nil, fmt.Errorf("create csr failed: %s", err.Error())
	}

	data, err := bcx509.CreateCertificateRequest(rand.Reader, template, csrConf.PrivateKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("create csr failed: %s", err.Error())
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: data}), nil
}

//Build the KeyUsage and ExtKeyUsage of the certificate based on the role and purpose of the certificate
// nolint: gocyclo
func getKeyUsageAndExtKeyUsage(userType db.UserType,
	certUsage db.CertUsage) (x509.KeyUsage, []x509.ExtKeyUsage) {
	var (
		keyUsage    x509.KeyUsage
		extKeyUsage []x509.ExtKeyUsage
	)
	if userType == db.INTERMRDIARY_CA || userType == db.ROOT_CA {
		keyUsage = x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	}
	if userType == db.USER_ADMIN || userType == db.USER_CLIENT ||
		userType == db.NODE_COMMON || userType == db.NODE_CONSENSUS {
		switch certUsage {
		case db.TLS_ENC:
			keyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement
		case db.TLS_SIGN:
			keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		case db.SIGN:
			keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		case db.TLS:
			keyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement |
				x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		}
	}
	if userType == db.NODE_COMMON || userType == db.NODE_CONSENSUS {
		if certUsage == db.TLS_ENC || certUsage == db.TLS_SIGN || certUsage == db.TLS {
			extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}
	}
	if userType == db.USER_ADMIN || userType == db.USER_CLIENT {
		if certUsage == db.TLS_ENC || certUsage == db.TLS_SIGN || certUsage == db.TLS {
			extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	}
	return keyUsage, extKeyUsage
}

type CSRRequest struct {
	OrgId      string
	UserId     string
	UserType   db.UserType
	Country    string
	Locality   string
	Province   string
	PrivateKey crypto.PrivateKey
}

//Build CSR request config
func BuildCSRReqConf(csrReq *CSRRequest) *CSRRequestConfig {
	organizationalUnit := db.UserType2NameMap[csrReq.UserType]
	organization := csrReq.OrgId
	var commonName string
	if csrReq.UserType == db.INTERMRDIARY_CA || csrReq.UserType == db.ROOT_CA {
		commonName = db.UserType2NameMap[csrReq.UserType]
	} else {
		commonName = csrReq.UserId
	}
	return &CSRRequestConfig{
		PrivateKey:         csrReq.PrivateKey,
		Country:            csrReq.Country,
		Locality:           csrReq.Locality,
		Province:           csrReq.Province,
		OrganizationalUnit: organizationalUnit,
		Organization:       organization,
		CommonName:         commonName,
	}
}

func generateCertTemplate(genConf *GenCertRequestConfig) (*x509.Certificate, error) {
	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, fmt.Errorf("generate cert template failed: %s", err.Error())
	}
	basicConstraintsValid := false
	isCA := false
	if genConf.UserType == db.INTERMRDIARY_CA || genConf.UserType == db.ROOT_CA {
		basicConstraintsValid = true
		isCA = true
	}

	var dnsName string
	if genConf.UserType == db.NODE_COMMON || genConf.UserType == db.NODE_CONSENSUS {
		dnsName = genConf.CommonName
	}

	var defaultDomain string
	if len(defaultDomainFromConfig()) != 0 {
		defaultDomain = defaultDomainFromConfig()
	}

	keyUsage, extKeyUsage := getKeyUsageAndExtKeyUsage(genConf.UserType, genConf.CertUsage)

	notBefore := time.Now().Add(-10 * time.Minute).UTC()

	template := &x509.Certificate{
		SerialNumber:          sn,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(genConf.ValidTime).UTC(),
		BasicConstraintsValid: basicConstraintsValid,
		IsCA:                  isCA,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		DNSNames:              []string{dnsName, defaultDomain},
		Subject: pkix.Name{
			Country:            genConf.Country,
			Locality:           genConf.Locality,
			Province:           genConf.Province,
			OrganizationalUnit: genConf.OrganizationalUnit,
			Organization:       genConf.Organization,
			CommonName:         genConf.CommonName,
		},
		Extensions:      genConf.Extension,
		ExtraExtensions: genConf.ExtraExtensions,
	}
	return template, nil
}

func getSignatureAlgorithm(privKey crypto.PrivateKey) x509.SignatureAlgorithm {
	signatureAlgorithm := x509.ECDSAWithSHA256
	switch privKey.PublicKey().ToStandardKey().(type) {
	case *rsa.PublicKey:
		signatureAlgorithm = x509.SHA256WithRSA
	case *sm2.PublicKey:
		signatureAlgorithm = x509.SignatureAlgorithm(bcx509.SM3WithSM2)
	}

	return signatureAlgorithm
}

//Convert certbyte to certcontent and X509 certificates
func ConvertToCertContent(certBytes []byte) (cert *x509.Certificate, certContent *db.CertContent, err error) {
	cert, err = ParseCertificate(certBytes)
	if err != nil {
		return
	}
	var extKeyUsageStr string
	extKeyUsageStr, err = ExtKeyUsageToString(cert.ExtKeyUsage)
	if err != nil {
		return
	}
	certContent = &db.CertContent{
		SerialNumber:       cert.SerialNumber.Int64(),
		Content:            string(certBytes),
		Signature:          hex.EncodeToString(cert.Signature),
		Country:            cert.Subject.Country[0],
		Locality:           cert.Subject.Locality[0],
		Province:           cert.Subject.Province[0],
		Organization:       cert.Subject.Organization[0],
		OrganizationalUnit: cert.Subject.OrganizationalUnit[0],
		CommonName:         cert.Subject.CommonName,
		Ski:                hex.EncodeToString(cert.SubjectKeyId),
		Aki:                hex.EncodeToString(cert.AuthorityKeyId),
		KeyUsage:           int(cert.KeyUsage),
		ExtKeyUsage:        extKeyUsageStr,
		IsCa:               cert.IsCA,
		IssueDate:          cert.NotBefore.Unix(),
		ExpirationDate:     cert.NotAfter.Unix(),
	}
	return
}

type UpdateCertConfig struct {
	OldCert         *x509.Certificate
	OldCsrBytes     []byte
	IssuerCertBytes []byte
	IssuerKey       crypto.PrivateKey
}

//Update cert info
func UpdateCert(updateConf *UpdateCertConfig) (*db.CertContent, error) {
	csrOriginal, err := ParseCsr(updateConf.OldCsrBytes)
	if err != nil {
		return nil, err
	}
	csr, err := bcx509.X509CertCsrToChainMakerCertCsr(csrOriginal)
	if err != nil {
		return nil, fmt.Errorf("update cert failed: %s", err.Error())
	}
	issuerCert, err := ParseCertificate(updateConf.IssuerCertBytes)
	if err != nil {
		return nil, err
	}
	x509certEncode, err := bcx509.CreateCertificate(rand.Reader, updateConf.OldCert, issuerCert,
		csr.PublicKey.ToStandardKey(), updateConf.IssuerKey.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("update cert failed: %s", err.Error())
	}

	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	extKeyUsageStr, err := ExtKeyUsageToString(updateConf.OldCert.ExtKeyUsage)
	if err != nil {
		return nil, err
	}
	certContent := &db.CertContent{
		SerialNumber:   updateConf.OldCert.SerialNumber.Int64(),
		Content:        string(certPemBytes),
		KeyUsage:       int(updateConf.OldCert.KeyUsage),
		ExtKeyUsage:    extKeyUsageStr,
		IsCa:           updateConf.OldCert.IsCA,
		IssueDate:      updateConf.OldCert.NotBefore.Unix(),
		ExpirationDate: updateConf.OldCert.NotAfter.Unix(),
	}
	return certContent, nil
}
