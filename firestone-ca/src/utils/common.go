/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"time"

	"chainmaker.org/chainmaker/common/v2/crypto"
)

const (
	//DefaultPrivateKeyPwd default private pwd
	DefaultPrivateKeyPwd = ""
	//DefaultWorkDirectory default work dir
	DefaultWorkDirectory = "./"
	//DefaultCRLNextTime default crl next time
	DefaultCRLNextTime = time.Hour * 24
	//DefaultTokenSecretKey default token secret key
	DefaultTokenSecretKey = "1045836262777123654"
)

var HashType2NameMap = map[crypto.HashType]string{
	crypto.HASH_TYPE_SM3:      "SM3",
	crypto.HASH_TYPE_SHA256:   "SHA256",
	crypto.HASH_TYPE_SHA3_256: "SHA3_256",
}

var Name2HashTypeMap = map[string]crypto.HashType{
	"SM3":      crypto.HASH_TYPE_SM3,
	"SHA256":   crypto.HASH_TYPE_SHA256,
	"SHA3_256": crypto.HASH_TYPE_SHA3_256,
}

type CaType int

const (
	//TLS catype of tls
	TLS CaType = iota + 1
	//SIGN catype of sign
	SIGN
	//SINGLE_ROOT catype of single_root
	SINGLE_ROOT
	//DOUBLE_ROOT catype of double_root
	DOUBLE_ROOT
)

//CaType2NameMap Ca type to string name
var CaType2NameMap = map[CaType]string{
	TLS:         "tls",
	SIGN:        "sign",
	SINGLE_ROOT: "single_root",
	DOUBLE_ROOT: "double_root",
}

//Name2CaTypeMap string name to ca type
var Name2CaTypeMap = map[string]CaType{
	"tls":         TLS,
	"sign":        SIGN,
	"single_root": SINGLE_ROOT,
	"double_root": DOUBLE_ROOT,
}
