package mdoc

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/google/go-cmp/cmp"
	"github.com/veraison/go-cose"
	"testing"
	"time"
)

func Test_coseX509Chain(t *testing.T) {
	rand := NewDeterministicRand()
	cert := createCA(t, rand, x509.Certificate{
		Subject:   pkix.Name{CommonName: "cert"},
		Issuer:    pkix.Name{CommonName: "cert"},
		NotBefore: time.UnixMilli(1000),
		NotAfter:  time.UnixMilli(2000),
	}).cert

	tests := []struct {
		name               string
		unprotectedHeaders cose.UnprotectedHeader
		want               []*x509.Certificate
		wantErr            error
	}{
		{
			name: "individual cert",
			unprotectedHeaders: cose.UnprotectedHeader{
				cose.HeaderLabelX5Chain: cert.Raw,
			},
			want: []*x509.Certificate{
				cert,
			},
		},
		{
			name: "multiple certs",
			unprotectedHeaders: cose.UnprotectedHeader{
				cose.HeaderLabelX5Chain: [][]byte{
					cert.Raw,
					cert.Raw,
				},
			},
			want: []*x509.Certificate{
				cert,
				cert,
			},
		},
		{
			name: "incorrect type",
			unprotectedHeaders: cose.UnprotectedHeader{
				cose.HeaderLabelX5Chain: 123,
			},
			wantErr: ErrUnrecognisedHeaderType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := coseX509Chain(tt.unprotectedHeaders)
			if err != tt.wantErr {
				t.Fatalf("Want err: %v, got: %v", tt.wantErr, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
