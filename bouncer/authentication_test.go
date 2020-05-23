package bouncer_test

import (
	"reflect"
	"testing"

	"github.com/kaancfidan/jwt-bouncer/bouncer"
)

func Test_authenticatorImpl_Authenticate(t *testing.T) {
	tests := []struct {
		name       string
		hmacKey    []byte
		authHeader string
		want       map[string]interface{}
		wantErr    bool
	}{
		{
			name:       "invalid token type",
			hmacKey:    []byte("TestKey"),
			authHeader: "this is not a valid bearer token",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := bouncer.NewAuthenticator(tt.hmacKey)

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
