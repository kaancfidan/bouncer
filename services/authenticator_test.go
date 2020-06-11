package services_test

import (
	"reflect"
	"testing"

	"github.com/kaancfidan/bouncer/models"
	"github.com/kaancfidan/bouncer/services"
)

func TestAuthenticatorImpl_Authenticate(t *testing.T) {
	tests := []struct {
		name          string
		signingKey    []byte
		signingMethod string
		cfg           models.AuthenticationConfig
		authHeader    string
		want          map[string]interface{}
		wantErr       bool
	}{
		{
			name:          "invalid auth header",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "this is not a valid bearer token",
			want:       nil,
			wantErr:    true,
		},
		{
			name:          "invalid auth scheme",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "Basic blabla",
			want:       nil,
			wantErr:    true,
		},
		{
			name:          "invalid jwt",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer invalid",
			want:       nil,
			wantErr:    true,
		},
		{
			name:          "key validation fail",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"8qvU6CrwlVBvXmhbnr2lyKGAFKaTMshDxQE7W-1LM54",
			want:    nil,
			wantErr: true,
		},
		{
			name:          "key validation success",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want: map[string]interface{}{
				"test": "valid",
			},
			wantErr: false,
		},
		{
			name:          "bearer scheme case insensitive",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want: map[string]interface{}{
				"test": "valid",
			},
			wantErr: false,
		},
		{
			name:          "unsupported algorithm",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ.B2qcvz8Ks8eQoEI9WzYSyCnC2q3VCY" +
				"5TMvrI62uMCOfHEBuW68HBxFEFfqSNawURnGPGNJmBZW4h1iREU85eWC" +
				"b1WHI3dcDIaTVjBdxXLmpZdQLhsyPO2tUYnkM5YQHqwZiMK-goimopIOb" +
				"42hPXIthHM6scRijl-DW79nXXIEQ",
			want:    nil,
			wantErr: true,
		},
		{
			name:          "issuer missing",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
				Issuer:           "http://url/to/some/issuer",
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want:    nil,
			wantErr: true,
		},
		{
			name:          "issuer claim available but no valid issuer configured",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQiLCJpc3MiOiJodHRwOi8vdXJsL3RvL3NvbWUvaXNzdWVyIn0." +
				"-SdBeoR7nVevkZIhKh-QlAl64k5ZzKQoV71f3Q-Djcs",
			want: map[string]interface{}{
				"test": "valid",
				"iss":  "http://url/to/some/issuer",
			},
			wantErr: false,
		},
		{
			name:          "valid issuer",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
				Issuer:           "http://url/to/some/issuer",
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQiLCJpc3MiOiJodHRwOi8vdXJsL3RvL3NvbWUvaXNzdWVyIn0." +
				"-SdBeoR7nVevkZIhKh-QlAl64k5ZzKQoV71f3Q-Djcs",
			want: map[string]interface{}{
				"test": "valid",
				"iss":  "http://url/to/some/issuer",
			},
			wantErr: false,
		},
		{
			name:          "audience missing",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
				Audience:         "http://url/to/some/audience",
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want:    nil,
			wantErr: true,
		},
		{
			name:          "audience claim available but no valid audience configured",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQiLCJhdWQiOiJodHRwOi8vdXJsL3RvL3NvbWUvYXVkaWVuY2UifQ." +
				"QslmtoVNaP9OSeKRvkxeR_UBMTdXL6098xLtbJpx114",
			want: map[string]interface{}{
				"test": "valid",
				"aud":  "http://url/to/some/audience",
			},
			wantErr: false,
		},
		{
			name:          "valid audience",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
				Audience:         "http://url/to/some/audience",
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQiLCJhdWQiOiJodHRwOi8vdXJsL3RvL3NvbWUvYXVkaWVuY2UifQ." +
				"QslmtoVNaP9OSeKRvkxeR_UBMTdXL6098xLtbJpx114",
			want: map[string]interface{}{
				"test": "valid",
				"aud":  "http://url/to/some/audience",
			},
			wantErr: false,
		},
		{
			name:          "expired token",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: false,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQiLCJpYXQiOjE1OTA4NTAzMjUsImV4cCI6MTU5MDg1MDMyNn0." +
				"IXoMkKWQRWZUp1TklXmZw3PbQl2_XxL8MxomJLb00Ec",
			want:    nil,
			wantErr: true,
		},
		{
			name:          "required exp unavailable",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: false,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want:    nil,
			wantErr: true,
		},
		{
			name:          "token used before iat",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQiLCJpYXQiOjMyNTAzNjgwMDAwfQ." +
				"Q_yvYtLhSEfEpA6hdTBZOwDKDWuYFVAdRA8juVbnltM",
			want:    nil,
			wantErr: true,
		},
		{
			name:          "token used before nbf",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  false,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQiLCJuYmYiOjMyNTAzNjgwMDAwfQ." +
				"5E-zZ8aJR7C2tIKdnDXUvVX9Z-T7ZUwlxZl668FJjWY",
			want:    nil,
			wantErr: true,
		},
		{
			name:          "required nbf unavailable",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  false,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want:    nil,
			wantErr: true,
		},
		{
			name: "unexpected alg in token",
			signingKey: []byte("-----BEGIN PUBLIC KEY-----\n" +
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3JaY7+LV0MHtD2+LsLus\n" +
				"/N6965JYFSc138UpaAeG9HK13LEhR8xqFMSgX0S7nrumDDERP3+/VXW+AOat8DZ/\n" +
				"HocrTuh1rQgQJgGFho/U0T9riTgm3eakFZi1Q2VjAYWIZizJ+wb+pttbGY1teLsW\n" +
				"1BDheuRmPiII/78bOb2ERD3KyWUEbyL+zjVdemq6RbTg4v/0L27yPS+WLceaUlbL\n" +
				"dBoJNjIKWF0odwQwqyp7KRN2KGR/SD9uWPL77KhWqNyhSHz7Ad9dYggnXbZg3d8O\n" +
				"B2qNUYi+Z+hAXs20noxYC3y4dQY0c7NmFirIKTMPRnfOGMCumKbhQ6Dlp5zrCC50\n" +
				"MwIDAQAB\n" +
				"-----END PUBLIC KEY-----"),
			signingMethod: "RSA",
			cfg: models.AuthenticationConfig{
				IgnoreExpiration: true,
				IgnoreNotBefore:  true,
			},
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := services.NewAuthenticator(
				tt.signingKey,
				tt.signingMethod,
				tt.cfg)

			if err != nil {
				t.Errorf("could not create authenticator: %v", err)
				return
			}

			got, err := a.Authenticate(tt.authHeader)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authenticate() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewAuthenticator(t *testing.T) {
	tests := []struct {
		name          string
		signingKey    []byte
		signingMethod string
		cfg           models.AuthenticationConfig
		wantErr       bool
	}{
		{
			name:          "hmac happy path",
			signingKey:    []byte("TestKey"),
			signingMethod: "HMAC",
			wantErr:       false,
		},
		{
			name:          "nil key",
			signingKey:    nil,
			signingMethod: "HMAC",
			wantErr:       true,
		},
		{
			name:          "unspecified signing method",
			signingKey:    nil,
			signingMethod: "",
			wantErr:       true,
		},
		{
			name:          "invalid signing method",
			signingKey:    []byte("some key"),
			signingMethod: "clearly not a signing method",
			wantErr:       true,
		},
		{
			name: "rsa happy path",
			signingKey: []byte("-----BEGIN PUBLIC KEY-----\n" +
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3JaY7+LV0MHtD2+LsLus\n" +
				"/N6965JYFSc138UpaAeG9HK13LEhR8xqFMSgX0S7nrumDDERP3+/VXW+AOat8DZ/\n" +
				"HocrTuh1rQgQJgGFho/U0T9riTgm3eakFZi1Q2VjAYWIZizJ+wb+pttbGY1teLsW\n" +
				"1BDheuRmPiII/78bOb2ERD3KyWUEbyL+zjVdemq6RbTg4v/0L27yPS+WLceaUlbL\n" +
				"dBoJNjIKWF0odwQwqyp7KRN2KGR/SD9uWPL77KhWqNyhSHz7Ad9dYggnXbZg3d8O\n" +
				"B2qNUYi+Z+hAXs20noxYC3y4dQY0c7NmFirIKTMPRnfOGMCumKbhQ6Dlp5zrCC50\n" +
				"MwIDAQAB\n" +
				"-----END PUBLIC KEY-----"),
			signingMethod: "RSA",
			wantErr:       false,
		},
		{
			name: "ecdsa happy path",
			signingKey: []byte("-----BEGIN PUBLIC KEY-----\n" +
				"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQPkk+EQIbNiOsa5W1dQsBgr98Jl\n" +
				"f3WzR1k8rcW0jCc3Bf0V/wqMdTcTL8yyyRjnMS6bABW1zHPnvjk/pV2+UQ==\n" +
				"-----END PUBLIC KEY-----"),
			signingMethod: "EC",
			wantErr:       false,
		},
		{
			name: "rsa invalid key",
			signingKey: []byte("-----BEGIN PUBLIC KEY-----\n" +
				"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQPkk+EQIbNiOsa5W1dQsBgr98Jl\n" +
				"f3WzR1k8rcW0jCc3Bf0V/wqMdTcTL8yyyRjnMS6bABW1zHPnvjk/pV2+UQ==\n" +
				"-----END PUBLIC KEY-----"),
			signingMethod: "RSA",
			wantErr:       true,
		},
		{
			name: "ec invalid key",
			signingKey: []byte("-----BEGIN PUBLIC KEY-----\n" +
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3JaY7+LV0MHtD2+LsLus\n" +
				"/N6965JYFSc138UpaAeG9HK13LEhR8xqFMSgX0S7nrumDDERP3+/VXW+AOat8DZ/\n" +
				"HocrTuh1rQgQJgGFho/U0T9riTgm3eakFZi1Q2VjAYWIZizJ+wb+pttbGY1teLsW\n" +
				"1BDheuRmPiII/78bOb2ERD3KyWUEbyL+zjVdemq6RbTg4v/0L27yPS+WLceaUlbL\n" +
				"dBoJNjIKWF0odwQwqyp7KRN2KGR/SD9uWPL77KhWqNyhSHz7Ad9dYggnXbZg3d8O\n" +
				"B2qNUYi+Z+hAXs20noxYC3y4dQY0c7NmFirIKTMPRnfOGMCumKbhQ6Dlp5zrCC50\n" +
				"MwIDAQAB\n" +
				"-----END PUBLIC KEY-----"),
			signingMethod: "EC",
			wantErr:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := services.NewAuthenticator(
				tt.signingKey,
				tt.signingMethod,
				tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewAuthenticator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
