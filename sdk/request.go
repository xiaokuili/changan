package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type Data struct {
	Key     string `json:"key"`
	RootPUB string `json:"rootpub"`
}

type Response struct {
	Code int    `json:"code"`
	Msg  string `json:"message"`
	Data Data   `json:"data"`
}

func Request(url, certID string) (string, error) {

	method := "POST"

	payload := strings.NewReader(`{` + "" + fmt.Sprintf(`"certSn": %s`, certID) + "" + `}`)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {

		return "", errors.New("请求token出错")
	}
	req.Header.Add("User-Agent", "Apifox/1.0.0 (https://www.apifox.cn)")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", errors.New("请求token出错")

	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.New("请求token出错")

	}
	resp := &Response{}
	err = json.Unmarshal(body, resp)
	if err != nil {
		return "", errors.New("请求token出错")

	}
	return resp.Data.Key, nil
}
