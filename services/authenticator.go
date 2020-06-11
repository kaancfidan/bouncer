package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/kaancfidan/bouncer/models"
)

// Authenticator interface
type Authenticator interface {
	Authenticate(authHeader string) (claims map[string]interface{}, err error)
}

// AuthenticatorImpl is a JWT based authentication implementation
type AuthenticatorImpl struct {
	signingKey    interface{}
	signingMethod string
	config        models.AuthenticationConfig
}

type claims struct {
	jwt.MapClaims
	ClockSkew int
}

func parseSigningKey(signingKey []byte, signingMethod string) (key interface{}, err error) {
	if signingMethod == "" {
		return nil, fmt.Errorf("signing method unspecified")
	}

	if len(signingKey) == 0 {
		return nil, fmt.Errorf("signing key is empty")
	}

	switch signingMethod {
	case "HMAC":
		key = signingKey
	case "RSA":
		key, err = jwt.ParseRSAPublicKeyFromPEM(signingKey)
		if err != nil {
			err = fmt.Errorf("could not parse RSA public key: %w", err)
		}
	case "EC":
		key, err = jwt.ParseECPublicKeyFromPEM(signingKey)
		if err != nil {
			err = fmt.Errorf("could not parse EC public key: %w", err)
		}
	default:
		err = fmt.Errorf("given signing method %s is out of range, "+
			"should be one of: [HMAC, RSA, EC]", signingMethod)
	}

	if err != nil {
		return nil, err
	}

	return key, nil
}

// NewAuthenticator creates a new AuthenticatorImpl instance
func NewAuthenticator(
	signingKey []byte,
	signingMethod string,
	config models.AuthenticationConfig) (*AuthenticatorImpl, error) {

	key, err := parseSigningKey(signingKey, signingMethod)
	if err != nil {
		return nil, fmt.Errorf("could not parse signing key: %w", err)
	}

	return &AuthenticatorImpl{
		signingKey:    key,
		signingMethod: signingMethod,
		config:        config,
	}, nil
}

func (a AuthenticatorImpl) keyFactory(token *jwt.Token) (interface{}, error) {
	return a.signingKey, nil
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
	claims := claims{
		MapClaims: jwt.MapClaims{},
		ClockSkew: a.config.ClockSkewInSeconds,
	}
	_, err := jwt.ParseWithClaims(tokenString, &claims, a.keyFactory)

	if err != nil {
		return nil, fmt.Errorf("error occurred while parsing claims: %w", err)
	}

	if _, ok := claims.MapClaims["exp"]; !ok && !a.config.IgnoreExpiration {
		return nil, fmt.Errorf("required expiration timestamp not found")
	}

	if _, ok := claims.MapClaims["nbf"]; !ok && !a.config.IgnoreNotBefore {
		return nil, fmt.Errorf("required not before timestamp not found")
	}

	// verify audience
	if a.config.Audience != "" {
		checkAud := claims.VerifyAudience(a.config.Audience, true)
		if !checkAud {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	// verify issuer
	if a.config.Issuer != "" {
		checkIss := claims.VerifyIssuer(a.config.Issuer, true)
		if !checkIss {
			return nil, fmt.Errorf("invalid issuer")
		}
	}

	return claims.MapClaims, nil
}

func (c *claims) VerifyExpiresAt(cmp int64, req bool) bool {
	return c.MapClaims.VerifyExpiresAt(cmp-int64(c.ClockSkew), req)
}

func (c *claims) VerifyIssuedAt(cmp int64, req bool) bool {
	return c.MapClaims.VerifyIssuedAt(cmp+int64(c.ClockSkew), req)
}

func (c *claims) VerifyNotBefore(cmp int64, req bool) bool {
	return c.MapClaims.VerifyNotBefore(cmp+int64(c.ClockSkew), req)
}

func (c *claims) Valid() error {
	err := new(jwt.ValidationError)
	now := time.Now().Unix()

	if !c.VerifyExpiresAt(now, false) {
		err.Inner = errors.New("token is expired")
		err.Errors |= jwt.ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now, false) {
		err.Inner = errors.New("token used before issued")
		err.Errors |= jwt.ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now, false) {
		err.Inner = errors.New("token is not valid yet")
		err.Errors |= jwt.ValidationErrorNotValidYet
	}

	if err.Errors == 0 {
		return nil
	}

	return err
}

func (c *claims) UnmarshalJSON(b []byte) error {
	var claims jwt.MapClaims
	err := json.Unmarshal(b, &claims)
	c.MapClaims = claims
	return err
}
