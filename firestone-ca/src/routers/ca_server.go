/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package routers

import (
	"chainmaker.org/chainmaker-ca/src/handlers"
	"github.com/gin-gonic/gin"
)

const ROUTERS_HEADER = "/api/ca"

func LoadCAServerRouter(e *gin.Engine) {
	routerGroup := e.Group(ROUTERS_HEADER)
	{
		routerGroup.POST("/gencertbycsr", handlers.GenCertByCsr())
		routerGroup.POST("/gencert", handlers.GenCert())
		routerGroup.POST("/querycerts", handlers.QueryCerts())
		routerGroup.POST("/renewcert", handlers.RenewCert())
		routerGroup.POST("/revokecert", handlers.RevokeCert())
		routerGroup.POST("/gencrl", handlers.GenCrl())
		routerGroup.POST("/gencsr", handlers.GenCsr())
		routerGroup.POST("/getnodeid", handlers.GetCertNodeId())
	}
}

func LoadLoginRouter(e *gin.Engine) {
	routerGroup := e.Group(ROUTERS_HEADER)
	routerGroup.POST("/login", handlers.Login())
}

func LoadDynamToken(e *gin.Engine) {
	routerGroup := e.Group(ROUTERS_HEADER)
	routerGroup.POST("/gendynamtoken", handlers.GenDynamToken())
}
