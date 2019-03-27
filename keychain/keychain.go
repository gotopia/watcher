package keychain

import (
	"crypto/rsa"
	"io/ioutil"
	"math/rand"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// PublicKey holds the internal state of the public key.
type PublicKey struct {
	Kid string
	Key *rsa.PublicKey
}

// PrivateKey holds the internal state of the private key.
type PrivateKey struct {
	Kid string
	Key *rsa.PrivateKey
}

// Keychain holds many public keys and private keys.
type Keychain struct {
	publicKeys  []*PublicKey
	privateKeys []*PrivateKey
	certs       map[string]string
}

// New returns a new keychain.
func New(dir string) *Keychain {
	k := &Keychain{
		certs: map[string]string{},
	}
	k.initWithKeyDir(dir)
	return k
}

const privateKeySuffix = ".key"
const publicKeySuffix = ".key.pub"

func (k *Keychain) initWithKeyDir(dir string) {
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		panic(err)
	}
	for _, info := range infos {
		filename := info.Name()
		pem, _ := ioutil.ReadFile(dir + "/" + info.Name())
		if err != nil {
			panic(err)
		}
		switch {
		case strings.HasSuffix(filename, privateKeySuffix):
			key, err := jwt.ParseRSAPrivateKeyFromPEM(pem)
			if err != nil {
				panic(err)
			}
			kid := strings.TrimSuffix(filename, privateKeySuffix)
			k.privateKeys = append(k.privateKeys, &PrivateKey{
				Kid: kid,
				Key: key,
			})
		case strings.HasSuffix(filename, publicKeySuffix):
			key, err := jwt.ParseRSAPublicKeyFromPEM(pem)
			if err != nil {
				panic(err)
			}
			kid := strings.TrimSuffix(filename, publicKeySuffix)
			k.publicKeys = append(k.publicKeys, &PublicKey{
				Kid: kid,
				Key: key,
			})
			k.certs[kid] = string(pem)
		default:
		}
	}
	if len(k.privateKeys) == 0 {
		panic("no key in this directory")
	}
	for _, key := range k.privateKeys {
		if _, ok := k.certs[key.Kid]; !ok {
			panic("some cert is missing")
		}
	}
}

// RandKey returns a random private key.
func (k *Keychain) RandKey() *PrivateKey {
	l := len(k.privateKeys)
	idx := rand.Intn(l)
	return k.privateKeys[idx]
}

// Certs returns the certs in the keychain.
func (k *Keychain) Certs() map[string]string {
	return k.certs
}
