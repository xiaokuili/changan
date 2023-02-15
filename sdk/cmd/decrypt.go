package cmd

import (
	"encoding/base64"

	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/hash"
	"chainmaker.org/chainmaker/common/v2/crypto/sym/sm4"
)

func Decrypt(ca, crypted string) string {
	key, err := hash.Get(crypto.HASH_TYPE_SM3, []byte(ca))
	if err != nil {
		panic(err)
	}

	sm4 := sm4.SM4Key{Key: key[:16]}
	tmp, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		panic(err)
	}
	data, err := sm4.Decrypt([]byte(tmp))
	if err != nil {
		panic(err)
	}
	return string(data)

}
