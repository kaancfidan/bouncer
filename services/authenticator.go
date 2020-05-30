package services

import (
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// Authenticator interface
type Authenticator interface {
	Authenticate(authHeader string) (claims map[string]interface{}, err error)
}

// AuthenticatorImpl is a JWT based authentication implementation
type AuthenticatorImpl struct {
	keyFunc            func(*jwt.Token) (interface{}, error)
	validIssuer        string
	validAudience      string
	expirationRequired bool
	notBeforeRequired  bool
}

// NewAuthenticator creates a new AuthenticatorImpl instance
func NewAuthenticator(
	hmacKey []byte,
	validIssuer string,
	validAudience string,
	expirationRequired bool,
	notBeforeRequired bool) *AuthenticatorImpl {
	return &AuthenticatorImpl{
		keyFunc: func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
				return hmacKey, nil
			}

			return nil, fmt.Errorf("unsupported signing algorithm: %v", token.Header["alg"])
		},
		validIssuer:        validIssuer,
		validAudience:      validAudience,
		expirationRequired: expirationRequired,
		notBeforeRequired:  notBeforeRequired,
	}
}

// Authenticate implements Bearer token authentication
func (a AuthenticatorImpl) Authenticate(authHeader string) (map[string]interface{}, error) {
	// check Bearer token
	splitToken := strings.Split(authHeader, " ")

	if len(splitToken) != 2 {
		return nil, fmt.Errorf("access token could not be extracted")
	}

	scheme := strings.ToLower(splitToken[0])
	tokenString := splitToken[1]

	if scheme != "bearer" {
		return nil, fmt.Errorf("authentication scheme expected to be \"bearer\", actual: %s", scheme)
	}

	// check claims for authorization
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, a.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("error occurred while parsing claims: %w", err)
	}

	if _, ok := claims["exp"]; !ok && a.expirationRequired {
		return nil, fmt.Errorf("required expiration timestamp not found")
	}

	if _, ok := claims["nbf"]; !ok && a.notBeforeRequired {
		return nil, fmt.Errorf("required not before timestamp not found")
	}

	// verify audience
	if a.validAudience != "" {
		checkAud := claims.VerifyAudience(a.validAudience, true)
		if !checkAud {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	// verify issuer
	if a.validIssuer != "" {
		checkIss := claims.VerifyIssuer(a.validIssuer, true)
		if !checkIss {
			return nil, fmt.Errorf("invalid issuer")
		}
	}

	return claims, nil
}
