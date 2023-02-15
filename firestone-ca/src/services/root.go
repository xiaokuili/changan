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

//Generate the root CA
func CreateRootCa() error {
	rootConfig := rootCaConfFromConfig()
	if rootConfig.CsrConf == nil {
		err := LoadRootCaFromConfig()
		if err != nil {
			return err
		}
		return nil
	}
	err := GenerateRootCa(rootConfig)
	if err != nil {
		return err
	}
	return nil
}

//Load root CA from the path in the configuration file
func LoadRootCaFromConfig() error {

	logger.Info("start loading root ca from config")
	caType, err := getCaType()
	if err != nil {
		return err
	}

	logger.Debug("load root ca from config", zap.String("ca type", utils.CaType2NameMap[caType]))

	switch caType {
	case utils.DOUBLE_ROOT:
		err := LoadDoubleRootCa()
		if err != nil {
			return err
		}
	case utils.SINGLE_ROOT:
		signCertConf, err := checkRootSignConf()
		if err != nil {
			return err
		}

		logger.Debug("load double root ca", zap.Any("sign cert conf", signCertConf))

		err = LoadSingleRootCa(signCertConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.SIGN:
		signCertConf, err := checkRootSignConf()
		if err != nil {
			return err
		}

		logger.Debug("load double root ca", zap.Any("sign cert conf", signCertConf))

		err = LoadSingleRootCa(signCertConf, db.SIGN)
		if err != nil {
			return err
		}
	case utils.TLS:
		tlsCertConf, err := checkRootTlsConf()
		if err != nil {
			return err
		}

		logger.Debug("load double root ca", zap.Any("tls cert conf", tlsCertConf))

		err = LoadSingleRootCa(tlsCertConf, db.TLS)
		if err != nil {
			return err
		}
	}

	logger.Info("end up loading root ca from config")
	return nil
}

func loadRootCaFromConfig(certPath, privateKeyPath string, certUsage db.CertUsage) error {
	keyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("load root ca failed: %s", err.Error())
	}
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("load root ca failed: %s", err.Error())
	}
	keyPair, _, err := ConvertToKeyPair(keyBytes)
	if err != nil {
		return err
	}
	cert, certContent, err := ConvertToCertContent(certBytes)
	if err != nil {
		return err
	}

	logger.Debug("loaf root ca from config", zap.Any("cert content", certContent))

	conditions := &CertConditions{
		UserType:  db.ROOT_CA,
		CertUsage: certUsage,
		UserId:    cert.Subject.CommonName,
		OrgId:     cert.Subject.Organization[0],
	}
	if exsitRootCA(conditions.UserId, conditions.OrgId, certUsage) {
		logger.Info("the load ca info from config is already exist")
		return nil
	}
	certInfo, err := CreateCertInfo(certContent, keyPair.Ski, conditions)
	if err != nil {
		return err
	}

	logger.Debug("load root ca from config", zap.Any("cert info", certInfo))

	err = models.CreateCertAndInfoTransaction(certContent, certInfo)
	if err != nil {
		return err
	}

	return nil
}

//Load double root CA from the path in the configuration file
func LoadDoubleRootCa() error {
	signCertConf, err := checkRootSignConf()
	if err != nil {
		return err
	}
	logger.Debug("load double root ca", zap.Any("sign cert conf", signCertConf))
	tlsCertConf, err := checkRootTlsConf()
	if err != nil {
		return err
	}
	logger.Debug("load double root ca", zap.Any("tls cert conf", tlsCertConf))
	err = loadRootCaFromConfig(signCertConf.CertPath, signCertConf.PrivateKeyPath, db.SIGN)
	if err != nil {
		return err
	}
	err = loadRootCaFromConfig(tlsCertConf.CertPath, tlsCertConf.PrivateKeyPath, db.TLS)
	if err != nil {
		return err
	}
	return nil
}

//Load single root CA from the path in the configuration file
func LoadSingleRootCa(certConf *utils.CertConf, certUsage db.CertUsage) error {
	return loadRootCaFromConfig(certConf.CertPath, certConf.PrivateKeyPath, certUsage)
}

//Generate root CA
func GenerateRootCa(rootCaConf *utils.CaConfig) error {
	logger.Info("start generating root ca")
	caType, err := getCaType()
	if err != nil {
		return err
	}

	logger.Debug("generate root ca", zap.String("ca type", utils.CaType2NameMap[caType]))

	switch caType {
	case utils.DOUBLE_ROOT:
		err := GenerateDoubleRootCa(rootCaConf.CsrConf)
		if err != nil {
			return err
		}
	case utils.SINGLE_ROOT:
		signCertConf, err := checkRootSignConf()
		if err != nil {
			return err
		}
		logger.Debug("generate double root ca", zap.Any("sign cert conf", signCertConf))
		err = GenerateSingleRootCa(rootCaConf.CsrConf, signCertConf, db.SIGN, signCertConf.KeyId)
		if err != nil {
			return err
		}
	case utils.SIGN:
		signCertConf, err := checkRootSignConf()
		if err != nil {
			return err
		}
		logger.Debug("generate double root ca", zap.Any("sign cert conf", signCertConf))
		err = GenerateSingleRootCa(rootCaConf.CsrConf, signCertConf, db.SIGN, signCertConf.KeyId)
		if err != nil {
			return err
		}
	case utils.TLS:
		tlsCertConf, err := checkRootTlsConf()
		if err != nil {
			return err
		}
		logger.Debug("generate double root ca", zap.Any("sign cert conf", tlsCertConf))
		err = GenerateSingleRootCa(rootCaConf.CsrConf, tlsCertConf, db.TLS, tlsCertConf.KeyId)
		if err != nil {
			return err
		}
	}
	logger.Info("end up generating root ca end")
	return nil
}

//Generate double root CA
func GenerateDoubleRootCa(rootCsrConf *utils.CsrConf) error {
	signCertConf, err := checkRootSignConf()
	if err != nil {
		return err
	}
	logger.Debug("generate double root ca", zap.Any("sign cert conf", signCertConf))
	tlsCertConf, err := checkRootTlsConf()
	if err != nil {
		return err
	}
	logger.Debug("generate double root ca", zap.Any("tls cert conf", tlsCertConf))
	keyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	err = genRootCa(rootCsrConf, keyTypeStr, hashTypeStr, db.SIGN,
		signCertConf.PrivateKeyPath, signCertConf.CertPath, signCertConf.KeyId)
	if err != nil {
		return err
	}
	err = genRootCa(rootCsrConf, keyTypeStr, hashTypeStr, db.TLS,
		tlsCertConf.PrivateKeyPath, tlsCertConf.CertPath, tlsCertConf.KeyId)
	if err != nil {
		return err
	}
	return nil
}

//Generate single root CA
func GenerateSingleRootCa(rootCsrConf *utils.CsrConf, rootCertConf *utils.CertConf,
	certUsage db.CertUsage, keyId string) error {
	keyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	err := genRootCa(rootCsrConf, keyTypeStr, hashTypeStr, certUsage,
		rootCertConf.PrivateKeyPath, rootCertConf.CertPath, keyId)
	if err != nil {
		return err
	}
	return nil
}

func genRootCa(rootCsrConf *utils.CsrConf, keyTypeStr, hashTypeStr string,
	certUsage db.CertUsage, keyPath, certPath, keyId string) error {
	err := checkCsrConf(rootCsrConf)
	if err != nil {
		return err
	}

	logger.Debug("generate root ca", zap.Any("root csr", rootCsrConf))

	_, err = models.FindCertInfo(rootCsrConf.CN, rootCsrConf.O, certUsage, db.ROOT_CA)
	if err != nil {
		privateKey, keyPair, err := CreateKeyPairNoEnc(keyTypeStr, hashTypeStr, keyId)
		if err != nil {
			return err
		}
		rootCertReqConf := &RootCertRequestConfig{
			PrivateKey:         privateKey,
			Country:            rootCsrConf.Country,
			Province:           rootCsrConf.Province,
			Locality:           rootCsrConf.Locality,
			OrganizationalUnit: rootCsrConf.OU,
			Organization:       rootCsrConf.O,
			CommonName:         rootCsrConf.CN,
			ValidTime:          certVaildTimeFromConfig(),
			CertUsage:          certUsage,
			UserType:           db.ROOT_CA,
			HashType:           hashTypeStr,
		}
		certContent, err := IssueCertBySelf(rootCertReqConf)
		if err != nil {
			return err
		}
		certConditions := &CertConditions{
			UserType:  db.ROOT_CA,
			CertUsage: certUsage,
			UserId:    rootCsrConf.CN,
			OrgId:     rootCsrConf.O,
		}
		certInfo, err := CreateCertInfo(certContent, keyPair.Ski, certConditions)
		if err != nil {
			return err
		}

		logger.Debug("generate root ca", zap.Any("cert info", certInfo))

		err = models.CreateCertAndInfoTransaction(certContent, certInfo)
		if err != nil {
			return err
		}
		keyBytes := []byte(keyPair.PrivateKey)
		err = WirteFile(keyPath, keyBytes)
		if err != nil {
			return fmt.Errorf("generate root ca failed:: %s", err.Error())
		}
		certBytes := []byte(certContent.Content)
		err = WirteFile(certPath, certBytes)
		if err != nil {
			return fmt.Errorf("generate root ca failed: %s", err.Error())
		}
		return nil
	}
	logger.Info("the root ca of the csr is already exist")
	return nil
}

//Check if rootCA already exists
func exsitRootCA(cn, o string, certUsage db.CertUsage) bool {
	_, err := models.FindCertInfo(cn, o, certUsage, db.ROOT_CA)
	return err == nil
}

//Get root private from file
func GetRootPrivateKey(certUsage db.CertUsage) (crypto.PrivateKey, error) {
	if certUsage == db.TLS {
		tlsCertConf, err := checkRootTlsConf()
		if err != nil {
			err = fmt.Errorf("get root tls key path failed: %s", err.Error())
			return nil, err
		}
		issuerPrivateKeyBytes, err := ioutil.ReadFile(tlsCertConf.PrivateKeyPath)
		if err != nil {
			err = fmt.Errorf("get root tls key file failed: %s", err.Error())
			return nil, err
		}
		issuePrivateKey, err := ParsePrivateKey(issuerPrivateKeyBytes)
		if err != nil {
			err = fmt.Errorf("get root tls private key failed: %s", err.Error())
			return nil, err
		}
		return issuePrivateKey, nil
	}
	if certUsage == db.SIGN {
		signCertConf, err := checkRootSignConf()
		if err != nil {
			err = fmt.Errorf("get root sign key path failed: %s", err.Error())
			return nil, err
		}
		issuerPrivateKeyBytes, err := ioutil.ReadFile(signCertConf.PrivateKeyPath)
		if err != nil {
			err = fmt.Errorf("get root sign key file failed: %s", err.Error())
			return nil, err
		}
		issuePrivateKey, err := ParsePrivateKey(issuerPrivateKeyBytes)
		if err != nil {
			err = fmt.Errorf("get root sign private key failed: %s", err.Error())
			return nil, err
		}
		return issuePrivateKey, nil
	}
	return nil, fmt.Errorf("get root private key failed: cert usage is unsupport")
}
