package handlers

import (
	"encoding/base64"

	"chainmaker.org/chainmaker-ca/src/services"
	"chainmaker.org/chainmaker/common/v2/crypto"
	"chainmaker.org/chainmaker/common/v2/crypto/hash"
	"chainmaker.org/chainmaker/common/v2/crypto/sym/sm4"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

// Certificates are generated by the CSR
func GenDynamToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		var queryCertReq QueryCertReq
		if err := c.ShouldBindBodyWith(&queryCertReq, binding.JSON); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		encrypToken, err := services.GenDynamToken(&services.QueryCertsReq{
			CertSn:    queryCertReq.CertSn,
			OrgId:     queryCertReq.OrgId,
			UserId:    queryCertReq.UserId,
			UserType:  queryCertReq.UserType,
			CertUsage: queryCertReq.CertUsage,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp(encrypToken, c)
		return

	}
}

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