/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"chainmaker.org/chainmaker-ca/src/models"
	"chainmaker.org/chainmaker-ca/src/models/db"
	"chainmaker.org/chainmaker-ca/src/utils"
	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/x509"
	"go.uber.org/zap"
)

//Generate cert by csr
func GenCertByCsr(genCertByCsrReq *GenCertByCsrReq) (*ApplyCertResp, error) {
	err := CheckCert(genCertByCsrReq.OrgId, genCertByCsrReq.UserId, genCertByCsrReq.UserType, genCertByCsrReq.CertUsage)
	if err != nil {
		logger.Info("check the cert request failed", zap.Error(err))
		return nil, err
	}

	logger.Debug("the cert request", zap.Any("req", genCertByCsrReq))

	hashType, err := checkHashType(hashTypeFromConfig())
	if err != nil {
		logger.Info("check the cert request hash type failed", zap.Error(err))
		return nil, err
	}

	issuerPrivateKey, issuerCertBytes, err := searchIssuerCa(genCertByCsrReq.OrgId,
		genCertByCsrReq.UserType, genCertByCsrReq.CertUsage)
	if err != nil {
		logger.Info("search the issuer ca failed", zap.Error(err))
		return nil, err
	}

	certRequestConfig := &CertRequestConfig{
		HashType:         hashType,
		IssuerPrivateKey: issuerPrivateKey,
		CsrBytes:         genCertByCsrReq.CsrBytes,
		IssuerCertBytes:  issuerCertBytes,
		ValidTime:        certVaildTimeFromConfig(),
		CertUsage:        genCertByCsrReq.CertUsage,
		UserType:         genCertByCsrReq.UserType,
	}
	certContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		logger.Info("issue cert failed", zap.Error(err))
		return nil, err
	}

	certConditions := &CertConditions{
		UserType:  genCertByCsrReq.UserType,
		CertUsage: genCertByCsrReq.CertUsage,
		UserId:    genCertByCsrReq.UserId,
		OrgId:     genCertByCsrReq.OrgId,
	}
	certInfo, err := CreateCertInfo(certContent, "", certConditions)
	if err != nil {
		logger.Info("create cert info failed", zap.Error(err))
		return nil, err
	}

	logger.Debug("generate cert by csr", zap.Any("cert info", certInfo))

	err = models.CreateCertAndInfoTransaction(certContent, certInfo)
	if err != nil {
		logger.Info("create cert to db failed", zap.Error(err))
		return nil, err
	}

	logger.Debug("generate cert by csr successfully", zap.String("cert", certContent.Content))
	return &ApplyCertResp{
		IssueCertSn: certInfo.IssuerSn,
		CertSn:      certContent.SerialNumber,
		CertContent: certContent.Content,
	}, nil
}

//Generate cert
func GenCert(genCertReq *GenCertReq) (*ApplyCertResp, error) {
	err := CheckCert(genCertReq.OrgId, genCertReq.UserId, genCertReq.UserType, genCertReq.CertUsage)
	if err != nil {
		logger.Info("check the cert request failed", zap.Error(err))
		return nil, err
	}

	logger.Debug("the cert request", zap.Any("req", genCertReq))

	privateKeyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()

	if len(genCertReq.PrivateKeyPwd) != 0 && isKeyEncryptFromConfig() && genCertReq.UserType == db.INTERMRDIARY_CA {
		err := fmt.Errorf("the ca key encryption is not supported")
		logger.Sugar().Infof(err.Error())
		return nil, err
	}

	privateKeyPwd := genCertReq.PrivateKeyPwd
	privateKey, keyPair, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr,
		privateKeyPwd, NO_PKCS11_KEY_ID)
	if err != nil {
		logger.Info("create key pair failed", zap.Error(err))
		return nil, err
	}
	csrRequest := &CSRRequest{
		OrgId:      genCertReq.OrgId,
		UserId:     genCertReq.UserId,
		UserType:   genCertReq.UserType,
		Country:    genCertReq.Country,
		Locality:   genCertReq.Locality,
		Province:   genCertReq.Province,
		PrivateKey: privateKey,
	}
	csrRequestConf := BuildCSRReqConf(csrRequest)
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		logger.Info("create csr failed", zap.Error(err))
		return nil, err
	}

	issuerPrivateKey, issuerCertBytes, err := searchIssuerCa(genCertReq.OrgId, genCertReq.UserType, genCertReq.CertUsage)
	if err != nil {
		logger.Info("search issuer ca failed", zap.Error(err))
		return nil, err
	}
	hashType, err := checkHashType(hashTypeFromConfig())
	if err != nil {
		logger.Info("check the cert request hash type failed", zap.Error(err))
		return nil, err
	}
	certRequestConfig := &CertRequestConfig{
		HashType:         hashType,
		CsrBytes:         csrByte,
		ValidTime:        certVaildTimeFromConfig(),
		CertUsage:        genCertReq.CertUsage,
		UserType:         genCertReq.UserType,
		IssuerPrivateKey: issuerPrivateKey,
		IssuerCertBytes:  issuerCertBytes,
	}
	certContent, err := IssueCertificate(certRequestConfig)
	if err != nil {
		logger.Info("issue the cert failed", zap.Error(err))
		return nil, err
	}
	certConditions := &CertConditions{
		UserType:  genCertReq.UserType,
		CertUsage: genCertReq.CertUsage,
		UserId:    genCertReq.UserId,
		OrgId:     genCertReq.OrgId,
	}
	certInfo, err := CreateCertInfo(certContent, keyPair.Ski, certConditions)
	if err != nil {
		logger.Info("create cert info failed", zap.Error(err))
		return nil, err
	}

	logger.Debug("generare cert", zap.Any("cert info", certInfo))

	err = models.CreateCertTransaction(certContent, certInfo, keyPair)
	if err != nil {
		logger.Info("create the cert to db failed", zap.Error(err))
		return nil, err
	}
	logger.Debug("generate cert", zap.String("cert", certContent.Content))
	logger.Debug("generate cert", zap.String("private key", keyPair.PrivateKey))
	return &ApplyCertResp{
		IssueCertSn: certInfo.IssuerSn,
		CertSn:      certContent.SerialNumber,
		CertContent: certContent.Content,
		PrivateKey:  keyPair.PrivateKey,
	}, nil
}

//Query certs
func QueryCerts(req *QueryCertsReq) ([]*CertInfos, error) {
	var (
		userType     db.UserType
		certUsage    db.CertUsage
		err          error
		certInfoList []*db.CertInfo
	)

	if req.CertSn != 0 {

		certInfo, err := models.FindCertInfoBySn(req.CertSn)
		if err != nil {
			logger.Info("find cert info by sn failed", zap.Error(err))
			return nil, err
		}
		certInfoList = append(certInfoList, certInfo)

	} else {
		userType, err = CheckParametersUserType(req.UserType)
		if err != nil {
			userType = 0
		}
		certUsage, err = checkParametersCertUsage(req.CertUsage)
		if err != nil {
			certUsage = 0
		}

		logger.Debug("query certs", zap.Any("req", req))

		certInfoList, err = models.FindCertInfos(req.UserId, req.OrgId, certUsage, userType)
		if err != nil {
			logger.Info("find cert infos failed", zap.Error(err))
			return nil, err
		}
	}

	var res []*CertInfos
	for _, certInfo := range certInfoList {

		certContent, err := models.FindCertContentBySn(certInfo.SerialNumber)
		if err != nil {
			logger.Info("find cert content by sn failed", zap.Error(err))
			return nil, err
		}

		isRevoked := true

		if _, err := models.QueryRevokedCertByRevokedSn(certInfo.SerialNumber); err != nil {
			logger.Info("find revoked cert by sn failed", zap.Error(err))
			isRevoked = false
		}

		res = append(res, &CertInfos{
			UserId:         certInfo.UserId,
			OrgId:          certInfo.OrgId,
			UserType:       db.UserType2NameMap[certInfo.UserType],
			CertUsage:      db.CertUsage2NameMap[certInfo.CertUsage],
			CertSn:         certInfo.SerialNumber,
			IssuerSn:       certInfo.IssuerSn,
			CertContent:    certContent.Content,
			ExpirationDate: certContent.ExpirationDate,
			IsRevoked:      isRevoked,
		})
	}
	logger.Debug("query certs", zap.Any("resp", res))
	return res, nil
}

//renew the cert expiration date
func RenewCert(renewCertReq *RenewCertReq) (*ApplyCertResp, error) {
	logger.Debug("renew cert", zap.Int64("cert sn", renewCertReq.CertSn))

	certInfo, err := models.FindCertInfoBySn(renewCertReq.CertSn)
	if err != nil {
		logger.Info("find the cert info by sn failed", zap.Error(err))
		return nil, err
	}
	certContent, err := models.FindCertContentBySn(renewCertReq.CertSn)
	if err != nil {
		logger.Info("find the cert content by sn failed", zap.Error(err))
		return nil, err
	}
	issuerPrivateKey, issuerCertBytes, err := searchIssuerCa(certInfo.OrgId, certInfo.UserType, certInfo.CertUsage)
	if err != nil {
		logger.Info("search the issuer ca failed", zap.Error(err))
		return nil, err
	}
	csrBytes := []byte(certContent.CsrContent)
	oldCert, err := ParseCertificate([]byte(certContent.Content))
	if err != nil {
		logger.Info("parse the cert bytes to x509 cert failed", zap.Error(err))
		return nil, err
	}
	logger.Debug("renew cert", zap.Any("old cert expiration date", oldCert.NotAfter.UTC()))
	//renew invalid date
	oldCert.NotAfter = oldCert.NotAfter.Add(certVaildTimeFromConfig()).UTC()

	logger.Debug("renew cert", zap.Any("new cert expiration date", oldCert.NotAfter.UTC()))

	newCertContent, err := UpdateCert(&UpdateCertConfig{
		OldCert:         oldCert,
		OldCsrBytes:     csrBytes,
		IssuerCertBytes: issuerCertBytes,
		IssuerKey:       issuerPrivateKey,
	})
	if err != nil {
		logger.Info("update the cert failed", zap.Error(err))
		return nil, err
	}
	err = models.UpdateCertContent(certContent, newCertContent)
	if err != nil {
		logger.Info("update the cert content to db failed", zap.Error(err))
		return nil, err
	}
	logger.Debug("renew cert", zap.String("cert", newCertContent.Content))
	return &ApplyCertResp{
		IssueCertSn: certInfo.IssuerSn,
		CertSn:      newCertContent.SerialNumber,
		CertContent: newCertContent.Content,
	}, nil
}

//Revoke  certificate
func RevokeCert(revokeCertReq *RevokeCertReq) ([]byte, error) {
	logger.Debug("revoke cert", zap.Any("req", revokeCertReq))
	_, err := models.QueryRevokedCertByRevokedSn(revokeCertReq.RevokedCertSn)
	if err == nil { //find it and is already revoked
		err = fmt.Errorf("this cert had already been revoked")
		logger.Info("find the revoked cert failed", zap.Error(err))
		return nil, err
	}

	_, err = models.QueryRevokedCertByRevokedSn(revokeCertReq.IssuerCertSn)
	if err == nil { //find it and is already revoked
		err = fmt.Errorf("issuer cert had already been revoked")
		logger.Info("find the issuer cert failed", zap.Error(err))
		return nil, err
	}

	ok, err := searchCertChain(revokeCertReq.RevokedCertSn, revokeCertReq.IssuerCertSn)
	if err != nil {
		logger.Info("search the cert chain failed", zap.Error(err))
		return nil, err
	}
	if !ok {
		err = fmt.Errorf("issue cert is not in revoked cert chain")
		logger.Info("search the cert chain failed", zap.Error(err))
		return nil, err
	}
	issueCertInfo, err := models.FindCertInfoBySn(revokeCertReq.IssuerCertSn)
	if err != nil {
		logger.Info("find the cert info by sn failed", zap.Error(err))
		return nil, err
	}

	logger.Debug("issuer cert info", zap.Any("issuer cert info", issueCertInfo))

	revokedCertContent, err := models.FindCertContentBySn(revokeCertReq.RevokedCertSn)
	if err != nil {
		logger.Info("find the cert content by sn failed", zap.Error(err))
		return nil, err
	}
	revokedCert := &db.RevokedCert{
		OrgId:            issueCertInfo.OrgId,
		RevokedCertSN:    revokeCertReq.RevokedCertSn,
		Reason:           revokeCertReq.Reason,
		RevokedStartTime: time.Now().Unix(),
		RevokedEndTime:   revokedCertContent.ExpirationDate,
		RevokedBy:        revokeCertReq.IssuerCertSn,
	}
	err = models.InsertRevokedCert(revokedCert)
	if err != nil {
		logger.Info("insert the revoked cert to db failed", zap.Error(err))
		return nil, err
	}
	//create crl
	genCrlReq := &GenCrlReq{
		IssuerCertSn: revokeCertReq.IssuerCertSn,
	}

	crlBytes, err := GenCrl(genCrlReq)
	if err != nil {
		logger.Info("generate the crl failed", zap.Error(err))
		return nil, err
	}
	logger.Debug("revoke cert", zap.String("crl", string(crlBytes)))
	return crlBytes, nil
}

//Get the latest crl
func GenCrl(genCrlReq *GenCrlReq) ([]byte, error) {
	logger.Debug("generate crl", zap.Any("req", genCrlReq))

	issueCertUse, err := GetX509Certificate(genCrlReq.IssuerCertSn)
	if err != nil {
		logger.Info("get x509 cert failed", zap.Error(err))
		return nil, err
	}
	issueCertInfo, err := models.FindCertInfoBySn(genCrlReq.IssuerCertSn)
	if err != nil {
		logger.Info("find cert info by sn failed", zap.Error(err))
		return nil, err
	}

	logger.Debug("generate crl", zap.Any("issuer cert info", issueCertInfo))

	var issuePrivateKey crypto.PrivateKey
	if issueCertInfo.UserType == db.ROOT_CA {
		issuePrivateKey, err = GetRootPrivateKey(issueCertInfo.CertUsage)
		if err != nil {
			logger.Info("get root private key failed", zap.Error(err))
			return nil, err
		}
	} else {
		var issueKeyPair *db.KeyPair
		issueKeyPair, err = models.FindKeyPairBySki(issueCertInfo.PrivateKeyId)
		if err != nil {
			logger.Info("find the key pair by ski failed", zap.Error(err))
			return nil, err
		}
		issuePrivateKeyByte := []byte(issueKeyPair.PrivateKey)

		issuePrivateKey, err = ParsePrivateKey(issuePrivateKeyByte)
		if err != nil {
			logger.Info("convert key bytes to private key failed", zap.Error(err))
			return nil, err
		}
	}
	revokedCertsList, err := models.QueryRevokedCertByIssueSn(genCrlReq.IssuerCertSn)
	if err != nil {
		logger.Info("find the revoked cert by issue sn", zap.Error(err))
		return nil, err
	}
	var revokedCerts []pkix.RevokedCertificate
	for _, value := range revokedCertsList {
		revoked := pkix.RevokedCertificate{
			SerialNumber:   big.NewInt(value.RevokedCertSN),
			RevocationTime: time.Unix(value.RevokedEndTime, 0),
		}
		revokedCerts = append(revokedCerts, revoked)
	}
	now := time.Now()
	next := now.Add(utils.DefaultCRLNextTime)
	crlBytes, err := x509.CreateCRL(rand.Reader, issueCertUse, issuePrivateKey.ToStandardKey(), revokedCerts, now, next)
	if err != nil {
		logger.Info("create CRL failed", zap.Error(err))
		return nil, err
	}
	logger.Debug("generate crl", zap.String("crl", string(crlBytes)))
	return crlBytes, nil
}

//Generate csr
func GenCsr(genCsrReq *GenCsrReq) ([]byte, error) {

	logger.Debug("generate csr", zap.Any("req", genCsrReq))

	privateKeyTypeStr := keyTypeFromConfig()
	hashTypeStr := hashTypeFromConfig()
	privateKeyPwd := genCsrReq.PrivateKeyPwd
	privateKey, _, err := CreateKeyPair(privateKeyTypeStr, hashTypeStr,
		privateKeyPwd, NO_PKCS11_KEY_ID)
	if err != nil {
		logger.Info("create key pair failed", zap.Error(err))
		return nil, err
	}
	csrRequest := &CSRRequest{
		OrgId:      genCsrReq.OrgId,
		UserId:     genCsrReq.UserId,
		UserType:   genCsrReq.UserType,
		Country:    genCsrReq.Country,
		Locality:   genCsrReq.Locality,
		Province:   genCsrReq.Province,
		PrivateKey: privateKey,
	}
	csrRequestConf := BuildCSRReqConf(csrRequest)
	csrByte, err := createCSR(csrRequestConf)
	if err != nil {
		logger.Info("create CSR failed", zap.Error(err))
		return nil, err
	}
	logger.Debug("generate csr", zap.String("csr", string(csrByte)))
	return csrByte, nil
}

//check orgId userId usertype certusage and determine whether to provIde certificate service
func CheckParameters(orgId, userId, userTypeStr, certUsageStr string) (userType db.UserType,
	certUsage db.CertUsage, err error) {
	userType, err = CheckParametersUserType(userTypeStr)
	if err != nil {
		return
	}
	certUsage, err = checkParametersCertUsage(certUsageStr)
	if err != nil {
		return
	}

	if err = checkParamsOfCertReq(orgId, userId, userType, certUsage); err != nil {
		return
	}
	return
}

//check the string parametes if empty
func CheckParametersEmpty(parameters ...string) error {
	for _, parameter := range parameters {
		if len(parameter) == 0 {
			err := fmt.Errorf("check parameters failed: required parameters cannot be empty")
			return err
		}
	}
	return nil
}

// Check if the certificate already exists
func CheckCert(orgId string, userId string, userType db.UserType, certUsage db.CertUsage) error {
	if userType == db.ROOT_CA {
		return fmt.Errorf("the root CA cannot be issued temporarily")
	}

	if userType == db.INTERMRDIARY_CA {
		_, err := models.FindCertInfo("", orgId, certUsage, db.INTERMRDIARY_CA)
		if err == nil {
			return fmt.Errorf("the ca cert has already existed")
		}
		return nil
	}
	_, err := models.FindCertInfo(userId, orgId, certUsage, userType)
	if err == nil {
		return fmt.Errorf("the cert has already existed")
	}
	return nil
}

// Get tls cert node Id
func GetTLSCertNodeId(getNodeIdReq *GetTLSCertNodeIdReq) (nodeId string, err error) {
	if getNodeIdReq.CertSn != 0 {
		nodeId, err = models.FindNodeIdByCertSn(getNodeIdReq.CertSn)
		if err != nil {
			err = fmt.Errorf("get cert node id failed: %s", err.Error())
			return
		}
		return
	}

	if (getNodeIdReq.UserType != db.NODE_CONSENSUS && getNodeIdReq.UserType != db.NODE_COMMON) ||
		(getNodeIdReq.CertUsage == db.SIGN) {
		err = fmt.Errorf("get cert node id failed: the certificate does not have a nodeId")
		return
	}

	certInfo, err := models.FindCertInfos(getNodeIdReq.UserId, getNodeIdReq.OrgId,
		getNodeIdReq.CertUsage, getNodeIdReq.UserType)
	if err != nil {
		err = fmt.Errorf("get cert node id failed: %s", err.Error())
		return
	}
	if len(certInfo) == 0 {
		err = fmt.Errorf("get cert node id failed: the certificate does not exist")
		return
	}
	if len(certInfo) > 1 {
		err = fmt.Errorf("get cert node id failed: cannot locate a unique certificate, more conditions are required")
		return
	}
	nodeId, err = models.FindNodeIdByCertSn(certInfo[0].SerialNumber)
	if err != nil {
		err = fmt.Errorf("get cert node id failed: %s", err.Error())
		return
	}
	return
}
