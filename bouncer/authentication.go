package bouncer

import (
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// Authenticator interface
type Authenticator interface {
	Authenticate(authHeader string) (claims map[string]interface{}, err error)
}

type authenticatorImpl struct {
	keyFunc func(*jwt.Token) (interface{}, error)
}

func NewAuthenticator(hmacKey []byte) *authenticatorImpl {
	return &authenticatorImpl{
		keyFunc: func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
				return hmacKey, nil
			}

			return nil, fmt.Errorf("unsupported signing algorithm: %v", token.Header["alg"])
		},
	}
}

// Authenticate implements Bearer token authentication
func (a authenticatorImpl) Authenticate(authHeader string) (map[string]interface{}, error) {
	// check Bearer token
	splitToken := strings.Split(authHeader, "Bearer ")

	if len(splitToken) != 2 {
		return nil, fmt.Errorf("access token could not be extracted")
	}

	accessToken := splitToken[1]

	// check claims for authorization
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(accessToken, claims, a.keyFunc)

	if err != nil {
		return nil, fmt.Errorf("error occurred while parsing claims: %w", err)
	}

	return claims, nil
}
