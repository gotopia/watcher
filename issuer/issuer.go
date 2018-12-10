package issuer

import (
	"time"

	"github.com/gotopia/watcher/keychain"

	"github.com/dgrijalva/jwt-go"
)

const defaultDuration = 7 * 24 * time.Hour

// Issuer holds the issuer's internal state.
type Issuer struct {
	uri      string
	keychain *keychain.Keychain
	duration time.Duration
}

// New returns a new issuer.
func New(uri string, k *keychain.Keychain) *Issuer {
	return &Issuer{
		uri:      uri,
		keychain: k,
		duration: defaultDuration,
	}
}

// Sign a JSON web token for user.
func (i *Issuer) Sign(subject string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(i.duration).Unix(),
		Issuer:    i.uri,
		Subject:   subject,
	})
	privateKey := i.keychain.RandKey()
	token.Header["kid"] = privateKey.Kid
	tokenString, _ := token.SignedString(privateKey.Key)
	return tokenString
}

// SetDuration sets the valid duration of token.
func (i *Issuer) SetDuration(duration time.Duration) {
	i.duration = duration
}

// Keychain returns the keychain used by the issuer.
func (i *Issuer) Keychain() *keychain.Keychain {
	return i.keychain
}
