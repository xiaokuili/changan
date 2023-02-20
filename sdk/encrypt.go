package sdk

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	bcx509 "chainmaker.org/chainmaker/common/v2/crypto/x509"

	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/hash"
	"chainmaker.org/chainmaker/common/v2/crypto/sym/sm4"
)

// key is client pub
func (s *Security) EncryptData(data string) (string, error) {
	key := ReadCA(s.UserPath)
	pub, err := Public(key)
	if err != nil {
		return "", errors.New("加密出错")
	}
	// 1. hash
	k, err := hash.Get(crypto.HASH_TYPE_SM3, []byte(pub))
	if err != nil {
		return "", errors.New("加密出错")
	}

	// sm4 encrypt
	sm4 := sm4.SM4Key{Key: k[:16]}
	crypt, err := sm4.Encrypt([]byte(data))
	if err != nil {
		return "", errors.New("加密出错")
	}
	return base64.StdEncoding.EncodeToString(crypt), nil

}

func Public(CertContent string) (string, error) {
	cert, err := ParseCertificate([]byte(CertContent))
	if err != nil {
		return "", err
	}
	pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pub), nil
}

// ParseCertificate parse cert file to x.509 cert struct
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
