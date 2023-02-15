/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"chainmaker.org/chainmaker-ca/src/models/db"
	"chainmaker.org/chainmaker-ca/src/utils"
	"chainmaker.org/chainmaker/common/v2/cert"
	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/asym"
	"chainmaker.org/chainmaker/common/v2/crypto/pkcs11"
)

const NO_PKCS11_KEY_ID = "nopkcs11"

//CreatePrivKey create private key
func createPrivKey(keyTypeStr string, keyId string) (crypto.PrivateKey, error) {
	keyType, err := checkKeyType(keyTypeStr)
	if err != nil {
		return nil, err
	}

	if isPkcs11 := pkcs11StartOrNot(); isPkcs11 && keyId != NO_PKCS11_KEY_ID {
		pkcs11Config := NewPkcs11Config(WithPrivKeyId(keyId),
			WithPrivKeyType(keyType))
		if pkcs11Config.pkcs11Handle == nil {
			return nil, fmt.Errorf("generate key pair failed, new pkcs11 handle failed")
		}
		var privKey crypto.PrivateKey
		privKey, err = pkcs11.NewPrivateKey(pkcs11Config.pkcs11Handle,
			pkcs11Config.keyId, pkcs11Config.keyType)
		if err != nil {
			return nil, fmt.Errorf("generate key pair failed, %s", err.Error())
		}
		return privKey, nil
	}

	privKey, err := asym.GenerateKeyPair(keyType)
	if err != nil {
		return nil, fmt.Errorf("generate key pair [%s] failed, %s", keyTypeStr, err.Error())
	}
	return privKey, nil
}

//EncryptPrivKey encrypt private key
func encryptPrivKey(privKey crypto.PrivateKey, keyPwd string) ([]byte, error) {
	//slice encryption of the key
	pwd := utils.DefaultPrivateKeyPwd + keyPwd
	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encrypt private key failed: %s", err.Error())
	}
	privKeyPem, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privKeyBytes, []byte(pwd), x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key failed: %s", err.Error())
	}
	return pem.EncodeToMemory(privKeyPem), nil
}

//DecryptPrivKey decrypt private key
func decryptPrivKey(privKeyRaw []byte, keyPwd string) (crypto.PrivateKey, error) {
	privatePwd := utils.DefaultPrivateKeyPwd + keyPwd
	issuerPrivKey, err := asym.PrivateKeyFromPEM(privKeyRaw, []byte(privatePwd))
	if err != nil {
		return nil, fmt.Errorf("decrypt private key from PEM failed: %s", err.Error())
	}
	return issuerPrivKey, nil
}

//CreateKeyPair create key pair
func CreateKeyPair(privateKeyTypeStr, hashTypeStr, privateKeyPwd,
	keyId string) (privateKey crypto.PrivateKey, keyPair *db.KeyPair, err error) {

	privateKey, err = createPrivKey(privateKeyTypeStr, keyId)
	if err != nil {
		return
	}
	hashType, err := checkHashType(hashTypeStr)
	if err != nil {
		return
	}
	var (
		privKeyPemBytes []byte

		privateKeyPem string
	)
	if isKeyEncryptFromConfig() && len(privateKeyPwd) != 0 {
		privKeyPemBytes, err = encryptPrivKey(privateKey, string(privateKeyPwd))
		if err != nil {
			return
		}
		privateKeyPem = string(privKeyPemBytes)
	} else {
		privateKeyPem, _ = privateKey.String()
	}
	publicKeyPem, _ := privateKey.PublicKey().String()
	ski, err := cert.ComputeSKI(hashType, privateKey.PublicKey().ToStandardKey())
	if err != nil {
		err = fmt.Errorf("create key pair failed: %s", err.Error())
		return
	}
	keyPair = &db.KeyPair{
		Ski:        hex.EncodeToString(ski),
		PrivateKey: privateKeyPem,
		PublicKey:  publicKeyPem,
		HashType:   utils.Name2HashTypeMap[hashTypeStr],
		KeyType:    crypto.Name2KeyTypeMap[privateKeyTypeStr],
	}
	return
}

//CreateKeyPairNoEnc create key pair no encryption
func CreateKeyPairNoEnc(privateKeyTypeStr, hashTypeStr, keyId string) (privateKey crypto.PrivateKey,
	keyPair *db.KeyPair, err error) {
	privateKey, err = createPrivKey(privateKeyTypeStr, keyId)
	if err != nil {
		return
	}
	hashType, err := checkHashType(hashTypeStr)
	if err != nil {
		return
	}
	privateKeyPem, _ := privateKey.String()
	publicKeyPem, _ := privateKey.PublicKey().String()
	ski, err := cert.ComputeSKI(hashType, privateKey.PublicKey().ToStandardKey())
	if err != nil {
		err = fmt.Errorf("create key pair failed: %s", err.Error())
		return
	}
	keyPair = &db.KeyPair{
		Ski:        hex.EncodeToString(ski),
		PrivateKey: privateKeyPem,
		PublicKey:  publicKeyPem,
		HashType:   utils.Name2HashTypeMap[hashTypeStr],
		KeyType:    crypto.Name2KeyTypeMap[privateKeyTypeStr],
	}
	return
}

//Convert the password and privatekey bytes to keypair and privatekey
func ConvertToKeyPair(privateKeyBytes []byte) (keyPair *db.KeyPair, privateKey crypto.PrivateKey, err error) {
	var (
		hashType crypto.HashType
		keyType  crypto.KeyType
	)
	hashTypeStr := hashTypeFromConfig()
	hashType, err = checkHashType(hashTypeStr)
	if err != nil {
		return
	}
	keyTypeStr := keyTypeFromConfig()
	keyType, err = checkKeyType(keyTypeStr)
	if err != nil {
		return
	}

	privateKey, err = ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return
	}

	ski, err := cert.ComputeSKI(hashType, privateKey.PublicKey().ToStandardKey())
	if err != nil {
		err = fmt.Errorf("transfer private key to key pair failed: %s", err.Error())
		return
	}
	publicKeyPEM, _ := privateKey.PublicKey().String()
	keyPair = &db.KeyPair{
		Ski:        hex.EncodeToString(ski),
		PrivateKey: string(privateKeyBytes),
		PublicKey:  publicKeyPEM,
		HashType:   hashType,
		KeyType:    keyType,
	}
	return
}
