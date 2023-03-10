package services

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"chainmaker.org/chainmaker-ca/src/models/db"
	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/hash"
	"chainmaker.org/chainmaker/common/v2/crypto/sym/sm4"
)

func GenDynamToken(req *QueryCertsReq) (*DynamToken, error) {
	// search ca
	Certs, err := QueryCerts(req)
	var res []*CertInfos
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(Certs); i++ {

		Cert := Certs[i]
		if !Cert.IsRevoked {
			res = append(res, Cert)
		}
	}
	if len(res) != 1 {
		return nil, errors.New("此用户不提供此功能")
	}
	cert, err := ParseCertificate([]byte(res[0].CertContent))
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	// search root pub then add time.now
	rootPriv, err := GetRootPrivateKey(db.SIGN)
	if err != nil {
		return nil, err
	}
	root, err := rootPriv.PublicKey().String()
	if err != nil {
		return nil, err
	}
	// dynamToken: encrypt by sm4
	t := time.Now().Unix()
	st := strconv.FormatInt(t, 10)
	token, err := Encrypt(root, string(pub)+st)
	if err != nil {
		return nil, err
	}
	return &DynamToken{
		Key:     token,
		RootPUB: root,
	}, nil
}

func Encrypt(key, data string) (string, error) {
	//
	k, err := hash.Get(crypto.HASH_TYPE_SM3, []byte(key))
	if err != nil {
		return "", errors.New("加密失败")
	}

	sm4 := sm4.SM4Key{Key: k[:16]}
	crypt, err := sm4.Encrypt([]byte(data))
	if err != nil {
		return "", errors.New("加密失败")
	}
	return base64.StdEncoding.EncodeToString(crypt), nil

}
