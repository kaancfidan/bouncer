package services

import (
	"fmt"
	"strings"
	"time"

	"github.com/kaancfidan/bouncer/models"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Authenticator interface
type Authenticator interface {
	Authenticate(authHeader string) (claims map[string]any, err error)
}

// AuthenticatorImpl is a JWT based authentication implementation
type AuthenticatorImpl struct {
	key    jwk.Key
	config models.AuthenticationConfig
	alg    jwa.KeyAlgorithm
}

// NewAuthenticator creates a new AuthenticatorImpl instance
func NewAuthenticator(
	signingKey []byte,
	signingAlgorithm string,
	config models.AuthenticationConfig) (*AuthenticatorImpl, error) {

	key, err := jwk.FromRaw(signingKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse key: %v", err)
	}

	alg := jwa.KeyAlgorithmFrom(signingAlgorithm)
	if _, isInvalid := alg.(jwa.InvalidKeyAlgorithm); isInvalid {
		return nil, fmt.Errorf("unknown signing algorithm: %s", signingAlgorithm)
	}

	return &AuthenticatorImpl{
		key:    key,
		config: config,
		alg:    alg,
	}, nil
}

// Authenticate implements Bearer token authentication
func (a AuthenticatorImpl) Authenticate(authHeader string) (map[string]any, error) {
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
		jwt.WithKey(a.alg, a.key))

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	err = jwt.Validate(token, options...)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	return token.PrivateClaims(), nil
}
