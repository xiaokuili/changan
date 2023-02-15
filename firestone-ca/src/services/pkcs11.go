/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"strings"
	"sync"

	"chainmaker.org/chainmaker/common/v2/crypto"
	"go.uber.org/zap"

	"chainmaker.org/chainmaker/common/v2/crypto/pkcs11"
)

type Pkcs11Config struct {
	pkcs11Handle *pkcs11.P11Handle
	keyType      crypto.KeyType
	keyId        string
}

var once sync.Once
var p11Handle *pkcs11.P11Handle

func initPkcs11Handle() {
	once.Do(func() {
		if isPkcs11 := pkcs11StartOrNot(); isPkcs11 {
			pkcs11Conf := pkcs11FromConfig()
			pkcs11Conf.Hash = strings.ToUpper(pkcs11Conf.Hash)
			var err error
			p11Handle, err = pkcs11.New(pkcs11Conf.Library, pkcs11Conf.Label,
				pkcs11Conf.Password, pkcs11Conf.SessionCacheSize, pkcs11Conf.Hash)
			if err != nil {
				logger.Info("new pkcs11 failed", zap.Error(err))
				return
			}
		}
		logger.Info("pkcs11 is not enabled")
	})
}

type OptionFunc func(*Pkcs11Config)

func WithPrivKeyId(keyId string) OptionFunc {
	return func(pc *Pkcs11Config) {
		pc.keyId = keyId
	}
}

func WithPrivKeyType(keyType crypto.KeyType) OptionFunc {
	return func(pc *Pkcs11Config) {
		pc.keyType = keyType
	}
}

func NewPkcs11Config(opts ...OptionFunc) (p11Conf *Pkcs11Config) {
	initPkcs11Handle()
	p11Conf = &Pkcs11Config{
		pkcs11Handle: p11Handle,
	}
	for _, opt := range opts {
		opt(p11Conf)
	}
	return
}
