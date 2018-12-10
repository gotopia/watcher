package watcher

import (
	"crypto/rsa"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"gopkg.in/resty.v1"
)

type fetchCertResp struct {
	Certs  map[string]string `json:"certs"`
	Expiry time.Time
}

var fetchCertResps = map[string]*fetchCertResp{}

const httpStatusOK = "200 OK"
const cacheAge = 2 * time.Hour

func fetchKey(uri string, kid string) (key *rsa.PublicKey, err error) {
	r := fetchCertResps[uri]
	if r != nil && r.Expiry.After(time.Now()) && r.Certs[kid] != "" {
		cert := r.Certs[kid]
		return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	}
	resp, err := resty.R().SetResult(&r).Get(uri)
	if err != nil || resp.Status() != httpStatusOK {
		err = errors.Errorf("fail to fetch certs from uri: %v", uri)
		return
	}
	r.Expiry = time.Now().Add(cacheAge)
	fetchCertResps[uri] = r
	cert := r.Certs[kid]
	return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
}
