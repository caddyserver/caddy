package route53

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/mitchellh/goamz/aws"
)

var b64 = base64.StdEncoding

func sign(auth aws.Auth, path string, params map[string]string) {
	date := time.Now().In(time.UTC).Format(time.RFC1123)
	params["Date"] = date
	hash := hmac.New(sha256.New, []byte(auth.SecretKey))
	hash.Write([]byte(date))
	signature := make([]byte, b64.EncodedLen(hash.Size()))
	b64.Encode(signature, hash.Sum(nil))

	header := fmt.Sprintf("AWS3-HTTPS AWSAccessKeyId=%s,Algorithm=HmacSHA256,Signature=%s",
		auth.AccessKey, signature)
	params["X-Amzn-Authorization"] = string(header)
	if auth.Token != "" {
		params["X-Amz-Security-Token"] = auth.Token
	}
}
