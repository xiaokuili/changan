/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	"chainmaker.org/chainmaker-ca/src/models"
	"chainmaker.org/chainmaker-ca/src/models/db"
	"chainmaker.org/chainmaker-ca/src/utils"
	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/asym"
	"chainmaker.org/chainmaker/common/v2/crypto/pkcs11"
	bcx509 "chainmaker.org/chainmaker/common/v2/crypto/x509"
)

//WirteFile wirte file to file path
func WirteFile(filePath string, fileBytes []byte) error {
	dir, _ := path.Split(filePath)
	err := CreateDir(dir)
	if err != nil {
		return fmt.Errorf("wirte file failed: %s", err.Error())
	}
	err = ioutil.WriteFile(filePath, fileBytes, os.ModePerm)
	if err != nil {
		return fmt.Errorf("wirte file failed: %s", err.Error())
	}
	return nil
}

//ParseCertificate parse cert file to x.509 cert struct
func ParseCertificate(certBytes []byte) (*x509.Certificate, error) {
	var (
		cert *bcx509.Certificate
		err  error
	)
	block, rest := pem.Decode(certBytes)
	if block == nil {
		cert, err = bcx509.ParseCertificate(rest)
	} else {
		cert, err = bcx509.ParseCertificate(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse x509 cert failed: %s", err.Error())
	}
	return bcx509.ChainMakerCertToX509Cert(cert)
}

//Convert privatekey byte to privatekey
func ParsePrivateKey(privateKeyBytes []byte) (crypto.PrivateKey, error) {
	var (
		privateKey crypto.PrivateKey
		err        error
	)

	if isPkcs11 := pkcs11StartOrNot(); isPkcs11 {
		keyTypeStr := keyTypeFromConfig()
		var keyType crypto.KeyType
		keyType, err = checkKeyType(keyTypeStr)
		if err != nil {
			return nil, fmt.Errorf("parse private key failed: %s", err.Error())
		}
		pkcs11Config := NewPkcs11Config(WithPrivKeyId(string(privateKeyBytes)),
			WithPrivKeyType(keyType))
		if pkcs11Config.pkcs11Handle == nil {
			return nil, fmt.Errorf("parse private key failed, new pkcs11 handle failed")
		}
		privateKey, err = pkcs11.NewPrivateKey(pkcs11Config.pkcs11Handle,
			pkcs11Config.keyId, pkcs11Config.keyType)
		if err != nil {
			return nil, fmt.Errorf("parse private key failed: %s", err.Error())
		}
		return privateKey, nil
	}

	block, rest := pem.Decode(privateKeyBytes)
	if block == nil {
		privateKey, err = asym.PrivateKeyFromDER(rest)
	} else {
		privateKey, err = asym.PrivateKeyFromDER(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private bytes to private key failed: %s", err.Error())
	}
	return privateKey, nil
}

//Convert privatekey byte to privatekey
func KeyBytesToPrivateKey(privateKeyBytes []byte, keyPwd string) (privateKey crypto.PrivateKey, err error) {
	if !isKeyEncryptFromConfig() {
		privateKey, err = ParsePrivateKey(privateKeyBytes)
		if err != nil {
			return
		}
	}
	privateKey, err = decryptPrivKey(privateKeyBytes, keyPwd)
	if err != nil {
		return
	}
	return
}

//ParseCsr parse csr file to x.509 cert request
func ParseCsr(csrBytes []byte) (*x509.CertificateRequest, error) {
	var (
		csrBC *bcx509.CertificateRequest
		err   error
	)
	block, rest := pem.Decode(csrBytes)
	if block == nil {
		csrBC, err = bcx509.ParseCertificateRequest(rest)
	} else {
		csrBC, err = bcx509.ParseCertificateRequest(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse certificate request failed: %s", err.Error())
	}
	return bcx509.ChainMakerCertCsrToX509CertCsr(csrBC)
}

//CreateDir create dir
func CreateDir(dirPath string) error {
	_, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(dirPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("create dir failed: %s", err.Error())
			}
		} else {
			return fmt.Errorf("create dir failed: %s", err.Error())
		}
	}
	return nil
}

//Convert extkeyusage to string
func ExtKeyUsageToString(extKeyUsage []x509.ExtKeyUsage) (string, error) {
	var extKeyUsageStr []string
	for _, v := range extKeyUsage {
		vStr := strconv.Itoa(int(v))
		extKeyUsageStr = append(extKeyUsageStr, vStr)
	}
	jsonBytes, err := json.Marshal(extKeyUsageStr)
	if err != nil {
		return "", fmt.Errorf("parse extKeyUsage to string faield: %s", err.Error())
	}
	return string(jsonBytes), nil
}

func checkKeyType(keyTypeStr string) (crypto.KeyType, error) {
	var (
		keyType crypto.KeyType
		ok      bool
	)
	if keyType, ok = crypto.Name2KeyTypeMap[keyTypeStr]; !ok {
		return keyType, fmt.Errorf("check key type failed: key type is unsupport")
	}
	return keyType, nil
}

func checkHashType(hashTypeStr string) (crypto.HashType, error) {
	var (
		hashType crypto.HashType
		ok       bool
	)
	if hashType, ok = crypto.HashAlgoMap[hashTypeStr]; !ok {
		return hashType, fmt.Errorf("check hash type failed: hash type is unsupport")
	}
	return hashType, nil
}

func checkIntermediateCaConf() []*utils.ImCaConfig {
	if len(imCaConfFromConfig()) == 0 {
		return nil
	}
	return imCaConfFromConfig()
}

func checkParamsOfCertReq(orgId, userId string, userType db.UserType, certUsage db.CertUsage) error {
	if userType != db.INTERMRDIARY_CA && len(userId) == 0 {
		return fmt.Errorf("check params of req failed: userId cannot be empty")
	}
	if userType == db.ROOT_CA {
		return fmt.Errorf("check params of req failed: cannot apply for a CA of type root")
	}
	if userType == db.INTERMRDIARY_CA && !canIssueCa() {
		return fmt.Errorf("check params of req failed: cannot continue to apply for a intermediate CA")
	}
	caType, err := getCaType()
	if err != nil {
		return err
	}

	if certUsage == db.TLS || certUsage == db.TLS_ENC || certUsage == db.TLS_SIGN {
		if caType == utils.SIGN {
			return fmt.Errorf("check params of req failed: sign CA cannot issue a tls certificate")
		}
	}
	if certUsage == db.SIGN {
		if caType == utils.TLS {
			return fmt.Errorf("check params of req failed: tls CA cannot issue a sign certificate")
		}
	}

	orgGroup := provideServiceFor()

	if len(orgGroup) == 0 {
		return nil
	}

	for i := 0; i < len(orgGroup); i++ {
		if orgId == orgGroup[i] {
			return nil
		}
	}

	return fmt.Errorf("check params of req failed: the organization cannot be serviced")
}

//Check and convert usertype(string) ot db.UserType
func CheckParametersUserType(userTypeStr string) (db.UserType, error) {
	var (
		userType db.UserType
		ok       bool
	)
	if userType, ok = db.Name2UserTypeMap[userTypeStr]; !ok {
		err := fmt.Errorf("check user type failed: the user type does not meet the requirements")
		return userType, err
	}
	return userType, nil
}

func checkParametersCertUsage(certUsageStr string) (db.CertUsage, error) {
	var (
		certUsage db.CertUsage
		ok        bool
	)
	if certUsage, ok = db.Name2CertUsageMap[certUsageStr]; !ok {
		err := fmt.Errorf("check cert usage failed: the cert usage does not meet the requirements")
		return certUsage, err
	}
	return certUsage, nil
}

func getCaType() (utils.CaType, error) {
	var (
		caType utils.CaType
		ok     bool
	)
	if caType, ok = utils.Name2CaTypeMap[allConfig.GetCaType()]; !ok {
		return caType, fmt.Errorf("ca type is unsupport,supported types: [tls],[sign],[single_root],[double_root]")
	}
	return caType, nil
}

//Find the issuer by the orgid
func searchIssuerCa(orgId string, userType db.UserType, certUsage db.CertUsage) (issuerPrivateKey crypto.PrivateKey,
	issuerCertBytes []byte, err error) {
	caType, err := getCaType()
	if err != nil {
		return
	}
	issuerCertUsage := covertCertUsage(certUsage, caType)
	//Looking for an intermediate CA with the same orgid
	if userType == db.INTERMRDIARY_CA {
		return searchRootCa(issuerCertUsage)
	}
	var issuerCertInfo *db.CertInfo
	issuerCertInfo, err = models.FindCertInfo("", orgId, issuerCertUsage, db.INTERMRDIARY_CA)
	if err != nil {
		if checkIntermediateCaConf() != nil {
			issuerCertInfo, err = models.FindCertInfo("", "", issuerCertUsage, db.INTERMRDIARY_CA)
			if err != nil {
				return searchRootCa(issuerCertUsage)
			}
		} else {
			return searchRootCa(issuerCertUsage)
		}
	}
	var issuerCertContent *db.CertContent
	issuerCertContent, err = models.FindCertContentBySn(issuerCertInfo.SerialNumber)
	if err != nil {
		return
	}
	issuerCertBytes = []byte(issuerCertContent.Content)
	var issuerKeyPair *db.KeyPair
	issuerKeyPair, err = models.FindKeyPairBySki(issuerCertInfo.PrivateKeyId)
	if err != nil {
		return
	}
	deIssuerPK := []byte(issuerKeyPair.PrivateKey)
	if err != nil {
		return
	}

	issuerPrivateKey, err = ParsePrivateKey(deIssuerPK)
	if err != nil {
		return
	}
	return
}

func searchRootCa(certUsage db.CertUsage) (rootKey crypto.PrivateKey, rootCertBytes []byte, err error) {
	var rootConf *utils.CertConf
	if certUsage == db.SIGN {
		rootConf, err = checkRootSignConf()
		if err != nil {
			return
		}
	}
	if certUsage == db.TLS {
		rootConf, err = checkRootTlsConf()
		if err != nil {
			return
		}
	}

	issuerCertBytes, err := ioutil.ReadFile(rootConf.CertPath)
	if err != nil {
		var rootCertContent *db.CertContent
		rootCertContent, err = models.FindCertContent("", "", certUsage, db.ROOT_CA)
		if err != nil {
			return
		}
		rootCertBytes = []byte(rootCertContent.Content)
	} else {
		rootCertBytes = issuerCertBytes
	}

	var issuerPrivateKeyBytes []byte
	issuerPrivateKeyBytes, err = ioutil.ReadFile(rootConf.PrivateKeyPath)
	if err != nil {
		return
	}
	rootKey, err = ParsePrivateKey(issuerPrivateKeyBytes)
	if err != nil {
		return
	}
	return
}

func covertCertUsage(certUsage db.CertUsage, caType utils.CaType) db.CertUsage {
	if caType == utils.DOUBLE_ROOT {
		if certUsage == db.SIGN {
			return db.SIGN
		}
		return db.TLS
	}
	if caType == utils.SINGLE_ROOT || caType == utils.SIGN {
		return db.SIGN
	}
	return db.TLS
}

//Get X509 certificate by sn
func GetX509Certificate(sn int64) (*x509.Certificate, error) {
	certContent, err := models.FindCertContentBySn(sn)
	if err != nil {
		return nil, err
	}
	certContentByte := []byte(certContent.Content)
	certContentByteUse, err := ParseCertificate(certContentByte)
	if err != nil {
		return nil, err
	}
	return certContentByteUse, nil
}

func searchCertChain(certSn, issueSn int64) (bool, error) {
	if issueSn == 0 {
		return false, fmt.Errorf("can't search root cert chain")
	}
	certInfo, err := models.FindCertInfoBySn(certSn)
	if err != nil {
		return false, err
	}
	if certInfo.IssuerSn == issueSn {
		return true, nil
	}
	certSn = certInfo.IssuerSn
	if certSn == 0 {
		return false, nil
	}
	return searchCertChain(certSn, issueSn)
}

func checkCsrConf(csrConf *utils.CsrConf) error {
	if len(csrConf.Country) == 0 {
		csrConf.Country = DEFAULT_CSR_COUNTRIY
	}
	if len(csrConf.Locality) == 0 {
		csrConf.Locality = DEFAULT_CSR_LOCALITY
	}
	if len(csrConf.Province) == 0 {
		csrConf.Province = DEFAULT_CSR_PROVINCE
	}
	if _, ok := db.Name2UserTypeMap[csrConf.OU]; !ok {
		return fmt.Errorf("check the csr config failed: OU config is unsupported type")
	}
	if len(csrConf.O) == 0 {
		return fmt.Errorf("check the csr config failed: O can't be empty")
	}
	if len(csrConf.CN) == 0 {
		return fmt.Errorf("check the csr config failed: CN can't be empty")
	}
	return nil
}

func checkRootSignConf() (*utils.CertConf, error) {
	certConf := rootCertConfFromConfig()
	for _, v := range certConf {
		if v == nil {
			continue
		}
		v.CertType = strings.ToLower(v.CertType)
		if v.CertType == "sign" {
			return v, nil
		}
	}
	return nil, fmt.Errorf("the correct path to sign the cert was not found")
}

func checkRootTlsConf() (*utils.CertConf, error) {
	certConf := rootCertConfFromConfig()
	for _, v := range certConf {
		if v == nil {
			continue
		}
		v.CertType = strings.ToLower(v.CertType)
		if v.CertType == "tls" {
			return v, nil
		}
	}
	return nil, fmt.Errorf("the correct path to tls the cert was not found")
}

func checkAccessControlConf() ([]*AppInfo, error) {
	ok := IsAccessControlFromConfig()
	if !ok {
		return nil, nil
	}
	confs := accessControlFromConfig()
	if len(confs) == 0 {
		return nil, fmt.Errorf("the access control config can't be empty")
	}
	var appInfos []*AppInfo
	for _, v := range confs {
		if v == nil {
			continue
		}
		v.AppRole = strings.ToLower(v.AppRole)
		role, ok := db.Name2AccessRoleMap[v.AppRole]
		if !ok {
			err := fmt.Errorf("check app role failed: role type is unsupport")
			return nil, err
		}
		appInfos = append(appInfos, &AppInfo{
			AppId:   v.AppId,
			AppKey:  v.AppKey,
			AppRole: role,
		})
	}
	return appInfos, nil
}
