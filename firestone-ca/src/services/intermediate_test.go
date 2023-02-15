/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package services

import (
	"log"
	"testing"
)

func TestCreateIntermediateCA(t *testing.T) {
	TestInit(t)
	err := CreateIntermediateCA()
	if err != nil {
		log.Fatalf("create intermediate ca failed: %s", err.Error())
	}
}
