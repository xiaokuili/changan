package cmd

import (
	"encoding/base64"

	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/hash"
	"chainmaker.org/chainmaker/common/v2/crypto/sym/sm4"
)

func Encrypt(ca, data string) string {
	key, err := hash.Get(crypto.HASH_TYPE_SM3, []byte(ca))
	if err != nil {
		panic(err)
	}

	sm4 := sm4.SM4Key{Key: key[:16]}
	crypt, err := sm4.Encrypt([]byte(data))
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(crypt)

}
