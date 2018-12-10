package watcher

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

var validMethods = []string{"RS256"}

// Verify the jwt token from user.
func Verify(tokenString string, allowedIssuer string) (subject string, err error) {
	parser := &jwt.Parser{ValidMethods: validMethods}
	var claims jwt.StandardClaims
	_, err = parser.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (publicKey interface{}, er error) {
		if !claims.VerifyIssuer(allowedIssuer, true) {
			er = jwt.NewValidationError(fmt.Sprintf("invalid issuer: %v", claims.Issuer), jwt.ValidationErrorIssuer)
			return
		}
		kid := token.Header["kid"].(string)
		return fetchKey(claims.Issuer, kid)

	})
	if err != nil {
		return
	}
	subject = claims.Subject
	return
}
