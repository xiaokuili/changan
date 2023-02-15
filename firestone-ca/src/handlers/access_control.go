/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handlers

import (
	"errors"
	"fmt"

	"chainmaker.org/chainmaker-ca/src/models/db"
	"chainmaker.org/chainmaker-ca/src/services"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginReq
		if err := c.ShouldBind(&req); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		isUseJwt, err := services.InitAccessControl()
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}

		if !isUseJwt {
			err = errors.New("access control is not enabled, check the configuration file")
			ServerErrorJSONResp(err.Error(), c)
			return
		}

		if err := services.CheckParametersEmpty(req.AppId, req.AppKey); err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		token, err := services.GetAppToken(req.AppId, req.AppKey)
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp(&LoginResp{
			AccessToken: token,
			ExpiressIn:  services.TokenExpireSeconds,
		}, c)
	}
}

//JWTAuthMiddleware
func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req TokenReq
		if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
			InputErrorJSONResp(err.Error(), c)
			c.Abort()
			return
		}
		if len(req.Token) == 0 {
			err := fmt.Errorf("token can't be empty")
			InputMissingJSONResp(err.Error(), c)
			c.Abort()
			return
		}
		claims, err := services.ParseToken(req.Token)
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			c.Abort()
			return
		}
		c.Set("appId", claims.AppId)
		c.Set("appRole", claims.AppRole)
		c.Next()
	}
}

func accessControl(c *gin.Context) (db.AccessRole, error) {
	var role db.AccessRole
	v, ok := c.Get("appRole")
	if !ok {
		return role, fmt.Errorf("get role from gin context failed")
	}
	role, ok = v.(db.AccessRole)
	if !ok {
		return role, fmt.Errorf("get role from gin context failed: role type error")
	}
	return role, nil
}
