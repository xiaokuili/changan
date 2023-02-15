/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Service error response
func ServerErrorJSONResp(err string, c *gin.Context) {
	resp := &StandardResp{
		Code: SERVER_ERROR_RESP_CODE,
		Msg:  SERVER_ERROR_MSG,
		Data: err,
	}
	c.JSON(http.StatusOK, resp)
}

// Input error response
func InputErrorJSONResp(err string, c *gin.Context) {
	resp := &StandardResp{
		Code: INPUT_ERROR_RESP_CODE,
		Msg:  INPUT_ERROR_MSG,
		Data: err,
	}
	c.JSON(http.StatusOK, resp)
}

// Input empty response
func InputMissingJSONResp(err string, c *gin.Context) {
	resp := &StandardResp{
		Code: INPUT_MISSING_PESP_CODE,
		Msg:  INPUT_MISSING_MSG,
		Data: err,
	}
	c.JSON(http.StatusOK, resp)
}

// Successful response
func SuccessfulJSONResp(data interface{}, c *gin.Context) {
	resp := StandardResp{
		Code: SUCCESS_PESP_CODE,
		Msg:  SUCCESS_MSG,
		Data: data,
	}
	c.JSON(http.StatusOK, resp)
}
