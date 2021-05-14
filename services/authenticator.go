package services

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/kaancfidan/bouncer/models"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// Authenticator interface
type Authenticator interface {
	Authenticate(authHeader string) (claims map[string]interface{}, err error)
}

// AuthenticatorImpl is a JWT based authentication implementation
type AuthenticatorImpl struct {
	keySet jwk.Set
	config models.AuthenticationConfig
}

// NewAuthenticator creates a new AuthenticatorImpl instance
func NewAuthenticator(
	signingKey []byte,
	signingMethod string,
	config models.AuthenticationConfig) (*AuthenticatorImpl, error) {

	keySet := jwk.NewSet()

	var key jwk.Key
	switch signingMethod {
	case "HMAC":
		symKey := jwk.NewSymmetricKey()
		err := symKey.Set(jwk.AlgorithmKey, jwa.HS256)
		if err != nil {
			return nil, fmt.Errorf("could not set algorithm to key: %v", err)
		}

		err = symKey.FromRaw(signingKey)
		if err != nil {
			return nil, fmt.Errorf("invalid signing key: %v", err)
		}
		key = symKey
	case "RSA":
		block, _ := pem.Decode(signingKey)
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block containing the public key")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER encoded public key: %v", err)
		}

		rsaKey := jwk.NewRSAPublicKey()
		rawKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("signing key is not an RSA public key")
		}

		err = rsaKey.FromRaw(rawKey)
		if err != nil {
			return nil, fmt.Errorf("invalid signing key: %v", err)
		}
		key = rsaKey
	case "ECDSA":
		block, _ := pem.Decode(signingKey)
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block containing the public key")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER encoded public key: %v", err)
		}

		ecdsaKey := jwk.NewECDSAPublicKey()
		rawKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("signing key is not an ECDSA public key")
		}

		err = ecdsaKey.FromRaw(rawKey)
		if err != nil {
			return nil, fmt.Errorf("invalid signing key: %v", err)
		}
		key = ecdsaKey
	default:
		return nil, fmt.Errorf("invalid signing method %s", signingMethod)
	}

	keySet.Add(key)

	return &AuthenticatorImpl{
		keySet: keySet,
		config: config,
	}, nil
}

// Authenticate implements Bearer token authentication
func (a AuthenticatorImpl) Authenticate(authHeader string) (map[string]interface{}, error) {
	splitToken := strings.Split(authHeader, " ")

	if len(splitToken) != 2 {
		return nil, fmt.Errorf("invalid authentication header format")
	}

	scheme := strings.ToLower(splitToken[0])
	if scheme != "bearer" {
		return nil, fmt.Errorf("authentication scheme expected to be \"bearer\", actual: %s", scheme)
	}

	var options []jwt.ValidateOption

	if a.config.Issuer != "" {
		options = append(options, jwt.WithIssuer(a.config.Issuer))
	}

	if a.config.Audience != "" {
		options = append(options, jwt.WithAudience(a.config.Audience))
	}

	if a.config.ClockSkewInSeconds != 0 {
		options = append(options, jwt.WithAcceptableSkew(time.Duration(a.config.ClockSkewInSeconds)*time.Second))
	}

	payload := splitToken[1]
	token, err := jwt.Parse(
		[]byte(payload),
		jwt.WithKeySet(a.keySet),
		jwt.UseDefaultKey(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	err = jwt.Validate(token, options...)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	return token.PrivateClaims(), nil
}
