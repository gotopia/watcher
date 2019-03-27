package watcher

import (
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"gopkg.in/resty.v1"
)

type fetchCertResp struct {
	Certs  map[string]string `json:"certs"`
	Expiry time.Time
}

var fetchCertResps sync.Map

const httpStatusOK = "200 OK"
const cacheAge = 2 * time.Hour

func fetchKey(uri string, kid string) (key *rsa.PublicKey, err error) {
	var cr *fetchCertResp
	r, ok := fetchCertResps.Load(uri)
	if ok {
		cr, ok := r.(*fetchCertResp)
		if ok && cr.Expiry.After(time.Now()) && cr.Certs[kid] != "" {
			cert := cr.Certs[kid]
			return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		}
	}
	resp, err := resty.R().SetResult(&cr).Get(uri)
	if err != nil || resp.Status() != httpStatusOK {
		err = errors.Errorf("fail to fetch certs from uri: %v", uri)
		return
	}
	cr.Expiry = time.Now().Add(cacheAge)
	fetchCertResps.Store(uri, cr)
	cert, ok := cr.Certs[kid]
	if !ok {
		err = jwt.NewValidationError(fmt.Sprintf("invalid kid: %v", kid), jwt.ValidationErrorClaimsInvalid)
		return
	}
	return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
}
