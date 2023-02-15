/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"fmt"
	"io/ioutil"

	"chainmaker.org/chainmaker-ca/src/models"
	"chainmaker.org/chainmaker-ca/src/models/db"
	"chainmaker.org/chainmaker-ca/src/utils"
	"chainmaker.org/chainmaker/common/v2/crypto"
	"go.uber.org/zap"
)

//CreateIntermediateCA Create intermediate CA in the configuration file
func CreateIntermediateCA() error {
	if checkIntermediateCaConf() == nil {
		logger.Info("there is not find intermediate ca config")
		return nil
	}
	imCaConfs := imCaConfFromConfig()
	for i := 0; i < len(imCaConfs); i++ {
		if imCaConfs[i] == nil {
			return nil
		}
		err := checkCsrConf(imCaConfs[i].CsrConf)
		if err != nil {
			logger.Error("create intermediate ca failed", zap.Error(err))
			continue
		}

		logger.Debug("create intermediate ca", zap.Any("csr config", imCaConfs[i].CsrConf))

		if exsitIntermediateCA(imCaConfs[i].CsrConf) {
			logger.Info("the intermediate ca info is already exist")
			continue
		}
		err = createIntermediateCA(imCaConfs[i])
		if err != nil {
			return err
		}
	}
	return nil
}

//Check if intermediate CA already exists
func exsitIntermediateCA(csrConf *utils.CsrConf) bool {
	_, err := models.FindCertInfo(csrConf.CN, csrConf.O, 0, db.INTERMRDIARY_CA)
	return err == nil
}

func createIntermediateCA(caConfig *utils.ImCaConfig) error {
	logger.Info("start creating intermediate CA")
	caType, err := getCaType()
	if err != nil {
		return err
	}

	logger.Debug("create intermediate ca", zap.String("ca type", utils.CaType2NameMap[caType]))

	if caType == utils.SINGLE_ROOT || caType == utils.SIGN || caType == utils.TLS {
		err := GenSingleIntermediateCA(caConfig, caType)
		if err != nil {
			return err
		}
	}
	if caType == utils.DOUBLE_ROOT {
		err := GenDoubleIntermediateCA(caConfig)
		if err != nil {
			return err
		}
	}
	logger.Info("end up creating intermediate CA")
	return nil
}

//Generate intermediate CA if catype is single_root
func GenSingleIntermediateCA(caConfig *utils.ImCaConfig, caType utils.CaType) error {
	if caType == utils.TLS {
		tlsCertConf, err := checkRootTlsConf()
		if err != nil {
			return err
		}

		logger.Debug("generate single intermediate CA", zap.Any("root tls cert conf", tlsCertConf))

		err = genIntermediateCA(caConfig, db.TLS, tlsCertConf.PrivateKeyPath, tlsCertConf.CertPath)
		if err != nil {
			return err
		}
	}
	signCertConf, err := checkRootSignConf()
	if err != nil {
		return err
	}

	logger.Debug("generate single intermediate CA", zap.Any("root sign cert conf", signCertConf))

	err = genIntermediateCA(caConfig, db.SIGN, signCertConf.PrivateKeyPath, signCertConf.CertPath)
	if err != nil {
		return err
	}
	return nil
}

//Generate intermediate CA if catype is double_root
func GenDoubleIntermediateCA(caConfig *utils.ImCaConfig) error {
	signCertConf, err := checkRootSignConf()
	if err != nil {
		return err
	}
	logger.Debug("generate double intermediate CA", zap.Any("sign cert conf", signCertConf))
	err = genIntermediateCA(caConfig, db.SIGN, signCertConf.PrivateKeyPath, signCertConf.CertPath)
	if err != nil {
		return err
	}
	tlsCertConf, err := checkRootTlsConf()
	if err != nil {
		return err
	}
	logger.Debug("generate double intermediate CA", zap.Any("tls cert conf", tlsCertConf))
	err = genIntermediateCA(caConfig, db.TLS, tlsCertConf.PrivateKeyPath, tlsCertConf.CertPath)
	if err != nil {
		return err
	}
	return nil
}

func genIntermediateCA(caConfig *utils.ImCaConfig, certUsage db.CertUsage, rootKeyPath, rootCertPath string) error {
	keyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	generatePrivateKey, generateKeyPair, err := CreateKeyPair(keyTypeStr, hashTypeStr,
		"", caConfig.KeyId)
	if err != nil {
		return err
	}
	csrRequestConf := createCsrReqConf(caConfig.CsrConf, generatePrivateKey)
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		return err
	}
	certRequestConfig, err := createIMCACertReqConf(csrByte, certUsage, rootKeyPath, rootCertPath)
	if err != nil {
		return err
	}
	certContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		return err
	}
	certConditions := &CertConditions{
		UserType:  db.INTERMRDIARY_CA,
		CertUsage: certUsage,
		UserId:    caConfig.CsrConf.CN,
		OrgId:     caConfig.CsrConf.O,
	}
	certInfo, err := CreateCertInfo(certContent, generateKeyPair.Ski, certConditions)
	if err != nil {
		return err
	}

	logger.Debug("generate intermediate ca", zap.Any("cert info", certInfo))

	err = models.CreateCertTransaction(certContent, certInfo, generateKeyPair)
	if err != nil {
		return err
	}
	return nil
}

func createCsrReqConf(csrConfig *utils.CsrConf, privateKey crypto.PrivateKey) *CSRRequestConfig {
	return &CSRRequestConfig{
		PrivateKey:         privateKey,
		Country:            csrConfig.Country,
		Locality:           csrConfig.Locality,
		Province:           csrConfig.Province,
		OrganizationalUnit: csrConfig.OU,
		Organization:       csrConfig.O,
		CommonName:         csrConfig.CN,
	}
}

func createIMCACertReqConf(csrByte []byte, certUsage db.CertUsage, rootKeyPath, rootCertPath string) (*CertRequestConfig, error) {
	var issuerCertBytes []byte
	if rootCertPath != "" {
		var err error
		issuerCertBytes, err = ioutil.ReadFile(rootCertPath)
		if err != nil {
			return nil, fmt.Errorf("create intermediate ca cert req config failed: %s", err.Error())
		}

	} else {
		certInfo, err := models.FindCertInfo("", "", certUsage, db.ROOT_CA)
		if err != nil {
			return nil, err
		}
		certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
		if err != nil {
			return nil, err
		}
		issuerCertBytes = []byte(certContent.Content)
	}

	issuerPrivateKeyBytes, err := ioutil.ReadFile(rootKeyPath)
	if err != nil {
		return nil, fmt.Errorf("create intermediate ca cert req config failed: %s", err.Error())
	}

	issueprivateKey, err := ParsePrivateKey(issuerPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("create intermediate ca cert req config failed: %s", err.Error())
	}

	hashType, err := checkHashType(hashTypeFromConfig())
	if err != nil {
		return nil, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         hashType,
		IssuerPrivateKey: issueprivateKey,
		IssuerCertBytes:  issuerCertBytes,
		ValidTime:        certVaildTimeFromConfig(),
		CertUsage:        certUsage,
		UserType:         db.INTERMRDIARY_CA,
		CsrBytes:         csrByte,
	}

	return certRequestConfig, nil
}
