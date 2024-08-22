package mdoc

import (
	"crypto/x509"
	"errors"
	"github.com/google/go-cmp/cmp"
	"github.com/veraison/go-cose"
	"testing"
)

func TestX509Chain(t *testing.T) {
	tests := []struct {
		name               string
		unprotectedHeaders cose.UnprotectedHeader
		want               []*x509.Certificate
		wantErr            error
	}{
		{
			name: "individual cert",
			unprotectedHeaders: cose.UnprotectedHeader{
				cose.HeaderLabelX5Chain: IACA.Raw,
			},
			want: []*x509.Certificate{
				IACA,
			},
		},
		{
			name: "multiple certs",
			unprotectedHeaders: cose.UnprotectedHeader{
				cose.HeaderLabelX5Chain: [][]byte{
					IACA.Raw,
					IACA.Raw,
				},
			},
			want: []*x509.Certificate{
				IACA,
				IACA,
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
			got, err := X509Chain(tt.unprotectedHeaders)
			if err != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("sdf() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.wantErr != nil {
				t.Fatalf("sdf() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("sdf() = %s", diff)
			}
		})
	}
}
