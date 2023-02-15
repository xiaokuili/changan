/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

//CertType
type UserType int

//CertUsage
type CertUsage int

const (
	//ROOT_CA root ca
	ROOT_CA UserType = iota + 1
	//INTERMRDIARY_CA intermediatry ca
	INTERMRDIARY_CA
	//USER_ADMIN admin
	USER_ADMIN
	//USER_CLIENT client
	USER_CLIENT
	//NODE_CONSENSUS consensus
	NODE_CONSENSUS
	//NODE_COMMON common
	NODE_COMMON
)

const (
	//SIGN sign
	SIGN CertUsage = iota + 1
	//TLS tls
	TLS
	//TLS_SIGN tls-sign
	TLS_SIGN
	//TLS_ENC tls-enc
	TLS_ENC
)

//UserType2NameMap CertType to string name
var UserType2NameMap = map[UserType]string{
	ROOT_CA:         "root",
	INTERMRDIARY_CA: "ca",
	USER_ADMIN:      "admin",
	USER_CLIENT:     "client",
	NODE_CONSENSUS:  "consensus",
	NODE_COMMON:     "common",
}

//Name2UserTypeMap string name to cert type
var Name2UserTypeMap = map[string]UserType{
	"root":      ROOT_CA,
	"ca":        INTERMRDIARY_CA,
	"admin":     USER_ADMIN,
	"client":    USER_CLIENT,
	"consensus": NODE_CONSENSUS,
	"common":    NODE_COMMON,
}

//CertUsage2NameMap .
var CertUsage2NameMap = map[CertUsage]string{
	SIGN:     "sign",
	TLS:      "tls",
	TLS_SIGN: "tls-sign",
	TLS_ENC:  "tls-enc",
}

//Name2CertUsageMap .
var Name2CertUsageMap = map[string]CertUsage{
	"sign":     SIGN,
	"tls":      TLS,
	"tls-sign": TLS_SIGN,
	"tls-enc":  TLS_ENC,
}

type AccessRole int

const (
	//ADMIN admin
	ADMIN AccessRole = iota + 1
	//USER user
	USER
)

//AccessRole2NameMap .
var AccessRole2NameMap = map[AccessRole]string{
	ADMIN: "admin",
	USER:  "user",
}

//Name2AccessRoleMap .
var Name2AccessRoleMap = map[string]AccessRole{
	"admin": ADMIN,
	"user":  USER,
}
