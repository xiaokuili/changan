package sdk

import (
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/hash"
	"chainmaker.org/chainmaker/common/v2/crypto/sym/sm4"
)

type Security struct {
	Url      string
	RootPath string
	UserPath string
	CertID   string
}

func (s *Security) DecrypDatas(crypted []string) ([]string, error) {
	result := make([]string, 0)
	token, err := Request(s.Url, s.CertID)
	if err != nil {
		return nil, err
	}
	root := ReadCA(s.RootPath)
	for i := 0; i < len(crypted); i++ {
		t, err := DecrypData(root, token, crypted[i])
		if err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	return result, nil
}

func DecrypData(rootPub, token string, crypted string) (string, error) {
	key, err := DecrypToken(rootPub, token)
	if err != nil {
		return "", err

	}
	rst, err := Decrypt(key, crypted)
	if err != nil {
		return "", err

	}
	return rst, nil
}

func DecrypToken(rootPub string, token string) (string, error) {
	data, err := Decrypt(rootPub, token)
	if err != nil {
		return "", err

	}
	// sm4 解密，基于root ca
	t1 := data[len(data)-10:]
	t, err := strconv.ParseInt(t1, 10, 64)

	data = data[0 : len(data)-10]

	if err != nil {
		return "", errors.New("解密出错")
	}
	if time.Now().Unix()-t > 60*60*24*365 {
		return "", errors.New("解密出错")
	}
	// get ca
	return data, nil
}

func Decrypt(key, crypted string) (string, error) {
	// hash
	k, err := hash.Get(crypto.HASH_TYPE_SM3, []byte(key))
	if err != nil {
		return "", errors.New("解密出错")
	}

	sm4 := sm4.SM4Key{Key: k[:16]}

	tmp, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", errors.New("解密出错")
	}
	// decrypt
	data, err := sm4.Decrypt([]byte(tmp))
	if err != nil {
		return "", errors.New("解密出错")
	}
	return string(data), nil

}
