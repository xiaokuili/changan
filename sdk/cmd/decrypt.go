package cmd

import (
	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/hash"
	"chainmaker.org/chainmaker/common/v2/crypto/sym/sm4"
	"encoding/base64"
	"strconv"
	"time"
)

func DecrypData(rootPub, token string, crypted string) string {
	key := DecrypToken(rootPub, token)
	rst := Decrypt(key, crypted)
	return rst
}

func DecrypToken(rootPub string, token string) string {
	data := Decrypt(rootPub, token)
	// sm4 解密，基于root ca
	t1 := data[len(data)-10:]
	t, err := strconv.ParseInt(t1, 10, 64)

	data = data[0 : len(data)-10]

	if err != nil {
		panic("token 获取时间出错")
	}
	if time.Now().Unix()-t > 3600 {
		panic("token过期")
	}
	// get ca
	return data
}

func Decrypt(key, crypted string) string {
	// hash
	k, err := hash.Get(crypto.HASH_TYPE_SM3, []byte(key))
	if err != nil {
		panic(err)
	}

	sm4 := sm4.SM4Key{Key: k[:16]}

	tmp, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		panic(err)
	}
	// decrypt
	data, err := sm4.Decrypt([]byte(tmp))
	if err != nil {
		panic(err)
	}
	return string(data)

}
