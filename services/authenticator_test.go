package services_test

import (
	"reflect"
	"testing"

	"github.com/kaancfidan/bouncer/services"
)

func TestAuthenticatorImpl_Authenticate(t *testing.T) {
	tests := []struct {
		name          string
		hmacKey       []byte
		validIssuer   string
		validAudience string
		expRequired   bool
		nbfRequired   bool
		authHeader    string
		want          map[string]interface{}
		wantErr       bool
	}{
		{
			name:       "invalid auth header",
			hmacKey:    []byte("TestKey"),
			authHeader: "this is not a valid bearer token",
			want:       nil,
			wantErr:    true,
		},
		{
			name:       "invalid auth scheme",
			hmacKey:    []byte("TestKey"),
			authHeader: "Basic blabla",
			want:       nil,
			wantErr:    true,
		},
		{
			name:       "invalid jwt",
			hmacKey:    []byte("TestKey"),
			authHeader: "Bearer invalid",
			want:       nil,
			wantErr:    true,
		},
		{
			name:    "key validation fail",
			hmacKey: []byte("TestKey"),
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"8qvU6CrwlVBvXmhbnr2lyKGAFKaTMshDxQE7W-1LM54",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "key validation success",
			hmacKey: []byte("TestKey"),
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want: map[string]interface{}{
				"test": "valid",
			},
			wantErr: false,
		},
		{
			name:    "bearer scheme case insensitive",
			hmacKey: []byte("TestKey"),
			authHeader: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want: map[string]interface{}{
				"test": "valid",
			},
			wantErr: false,
		},
		{
			name:    "unsupported algorithm",
			hmacKey: []byte("TestKey"),
			authHeader: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ.B2qcvz8Ks8eQoEI9WzYSyCnC2q3VCY" +
				"5TMvrI62uMCOfHEBuW68HBxFEFfqSNawURnGPGNJmBZW4h1iREU85eWC" +
				"b1WHI3dcDIaTVjBdxXLmpZdQLhsyPO2tUYnkM5YQHqwZiMK-goimopIOb" +
				"42hPXIthHM6scRijl-DW79nXXIEQ",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "issuer missing",
			hmacKey: []byte("TestKey"),
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			validIssuer: "http://url/to/some/issuer",
			want:        nil,
			wantErr:     true,
		},
		{
			name:    "issuer claim available but no valid issuer configured",
			hmacKey: []byte("TestKey"),
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
			name:        "valid issuer",
			hmacKey:     []byte("TestKey"),
			validIssuer: "http://url/to/some/issuer",
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
			hmacKey:       []byte("TestKey"),
			validAudience: "http://url/to/some/audience",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "audience claim available but no valid audience configured",
			hmacKey: []byte("TestKey"),
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
			hmacKey:       []byte("TestKey"),
			validAudience: "http://url/to/some/audience",
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
			name:    "expired token",
			hmacKey: []byte("TestKey"),
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQiLCJpYXQiOjE1OTA4NTAzMjUsImV4cCI6MTU5MDg1MDMyNn0." +
				"IXoMkKWQRWZUp1TklXmZw3PbQl2_XxL8MxomJLb00Ec",
			want:    nil,
			wantErr: true,
		},
		{
			name:        "required exp unavailable",
			hmacKey:     []byte("TestKey"),
			expRequired: true,
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "token used before nbf",
			hmacKey: []byte("TestKey"),
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQiLCJuYmYiOjMyNTAzNjgwMDAwfQ." +
				"5E-zZ8aJR7C2tIKdnDXUvVX9Z-T7ZUwlxZl668FJjWY",
			want:    nil,
			wantErr: true,
		},
		{
			name:        "required nbf unavailable",
			hmacKey:     []byte("TestKey"),
			nbfRequired: true,
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJ0ZXN0IjoidmFsaWQifQ." +
				"BTAK2WX8VVVJC_mr2f0N89cx7d34HgXobLS6pKwJpdQ",
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := services.NewAuthenticator(
				tt.hmacKey,
				tt.validIssuer,
				tt.validAudience,
				tt.expRequired,
				tt.nbfRequired)

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
