/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handlers

const (
	//SUCCESS_PESP_CODE The code returned on successful request
	SUCCESS_PESP_CODE = 200
	//INPUT_MISSING_PESP_CODE The code returned if the required parameters are missing
	INPUT_MISSING_PESP_CODE = 202
	//INPUT_ERROR_RESP_CODE The code returned when an error is inputted
	INPUT_ERROR_RESP_CODE = 204
	//SERVER_ERROR_RESP_CODE The code returned by the server when an error occurred
	SERVER_ERROR_RESP_CODE = 500
)

const (
	//INPUT_MISSING_MSG  The msg returned if the required parameters are missing
	INPUT_MISSING_MSG = "Missing required parameters"
	//INPUT_ERROR_MSG The msg returned when an error is inputted
	INPUT_ERROR_MSG = "There is an error in the input parameter"
	//SERVER_ERROR_MSG The msg returned by the server when an error occurred
	SERVER_ERROR_MSG = "An error occurred with the internal service"
	//SUCCESS_MSG The msg returned on successful request
	SUCCESS_MSG = "The request service returned successfully"
)

type StandardResp struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

type LoginResp struct {
	AccessToken string `json:"accessToken"`
	ExpiressIn  int64  `json:"expiressIn"`
}
