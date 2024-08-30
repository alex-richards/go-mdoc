package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"
)

func TestVerifyChain(t *testing.T) {
	rand := NewDeterministicRand()

	root1 := createCA(
		t,
		rand,
		x509.Certificate{
			Subject:   pkix.Name{CommonName: "root1"},
			Issuer:    pkix.Name{CommonName: "root1"},
			NotBefore: time.UnixMilli(1000),
			NotAfter:  time.UnixMilli(2000),
		},
	)
	root2 := createCA(
		t,
		rand,
		x509.Certificate{
			SerialNumber: big.NewInt(5678),
			Subject:      pkix.Name{CommonName: "root2"},
			Issuer:       pkix.Name{CommonName: "root2"},
			NotBefore:    time.UnixMilli(1000),
			NotAfter:     time.UnixMilli(2000),
		},
	)

	roots := []*x509.Certificate{root1.cert, root2.cert}

	tests := []struct {
		name                   string
		roots                  []*x509.Certificate
		chain                  []*x509.Certificate
		now                    time.Time
		tinker                 func(chain []*x509.Certificate) []*x509.Certificate
		wantRootChecks         int
		wantIntermediateChecks int
		wantLeafChecks         int
		wantErr                error
	}{
		{
			name:  "single cert",
			roots: roots,
			chain: createChain(t, rand, root1, 1),
			now:   time.UnixMilli(1500),
		},
		{
			name:  "2 cert chain",
			roots: roots,
			chain: createChain(t, rand, root1, 2),
			now:   time.UnixMilli(1500),
		},
		{
			name:  "3 cert chain",
			roots: roots,
			chain: createChain(t, rand, root1, 3),
			now:   time.UnixMilli(1500),
		},
		{
			name:    "expired",
			roots:   roots,
			chain:   createChain(t, rand, root1, 1),
			now:     time.UnixMilli(500),
			wantErr: ErrInvalidCertificate,
		},
		{
			name:    "not yet valid",
			roots:   roots,
			chain:   createChain(t, rand, root1, 1),
			now:     time.UnixMilli(2500),
			wantErr: ErrInvalidCertificate,
		},
		{
			name:    "unrooted chain",
			roots:   []*x509.Certificate{root2.cert},
			chain:   createChain(t, rand, root1, 1),
			now:     time.UnixMilli(2500),
			wantErr: ErrInvalidCertificate,
		},
		{
			name:  "broken chain",
			roots: roots,
			chain: createChain(t, rand, root1, 3),
			tinker: func(chain []*x509.Certificate) []*x509.Certificate {
				out := make([]*x509.Certificate, 0, len(chain)-1)
				out = append(out, chain[0:1]...)
				out = append(out, chain[2:]...)
				return out
			},
			now:     time.UnixMilli(1500),
			wantErr: ErrInvalidCertificate,
		},
		{
			name:    "nil roots",
			roots:   nil,
			wantErr: ErrNoRootCertificates,
		},
		{
			name:    "empty roots",
			roots:   []*x509.Certificate{},
			wantErr: ErrNoRootCertificates,
		},
		{
			name:    "empty chain",
			roots:   []*x509.Certificate{{}},
			chain:   []*x509.Certificate{},
			wantErr: ErrEmptyChain,
		},
		{
			name:    "nil chain",
			roots:   []*x509.Certificate{{}},
			chain:   nil,
			wantErr: ErrEmptyChain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var chain []*x509.Certificate
			if tt.tinker == nil {
				chain = tt.chain
			} else {
				chain = tt.tinker(tt.chain)
			}

			rootChecks := 1
			intermediateChecks := max(0, len(chain)-1)
			leafChecks := 1

			leafCertificate, err := verifyChain(
				tt.roots,
				chain,
				tt.now,
				func(rootCertificate *x509.Certificate) error {
					rootChecks--
					return nil
				},
				func(certificate *x509.Certificate, previous *x509.Certificate) error {
					intermediateChecks--
					return nil
				},
				func(certificate *x509.Certificate, previous *x509.Certificate) error {
					leafChecks--
					return nil
				},
			)

			if err != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err == nil && tt.wantErr != nil {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			if rootChecks != tt.wantRootChecks {
				t.Fatalf("rootChecks = %v, want %v", rootChecks, tt.wantRootChecks)
			}
			if intermediateChecks != tt.wantIntermediateChecks {
				t.Fatalf("intermediateChecks = %v, want %v", intermediateChecks, tt.wantIntermediateChecks)
			}
			if leafChecks != tt.wantLeafChecks {
				t.Fatalf("leafChecks = %v, want %v", leafChecks, tt.wantLeafChecks)
			}

			if leafCertificate == nil {
				t.Fatal("leafCertificate == nil")
			}
		})
	}
}

type ChainEntry struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func createCA(t *testing.T, rand io.Reader, template x509.Certificate) *ChainEntry {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		t.Fatal(err)
	}

	template.Version = 3
	template.SerialNumber = big.NewInt(1)
	template.Issuer = template.Subject
	template.NotBefore = time.UnixMilli(1000)
	template.NotAfter = time.UnixMilli(2000)
	template.BasicConstraintsValid = true
	template.IsCA = true

	der, err := x509.CreateCertificate(
		rand,
		&template,
		&template,
		key.Public(),
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return &ChainEntry{
		cert,
		key,
	}
}

func createChain(t *testing.T, rand io.Reader, ca *ChainEntry, len int) []*x509.Certificate {
	t.Helper()

	if ca == nil {
		t.Fatal()
	}

	previous := ca
	chain := make([]*x509.Certificate, 0, len)
	for i := 0; i < len; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand)
		if err != nil {
			t.Fatal(err)
		}

		template := &x509.Certificate{
			Version:               3,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("cert %d", i)},
			Issuer:                previous.cert.Subject,
			NotBefore:             time.UnixMilli(1000),
			NotAfter:              time.UnixMilli(2000),
			BasicConstraintsValid: true,
		}

		if i < len-1 {
			template.IsCA = true
			template.KeyUsage = x509.KeyUsageCertSign
		}

		der, err := x509.CreateCertificate(
			rand,
			template,
			previous.cert,
			key.Public(),
			previous.key,
		)
		if err != nil {
			t.Fatal(err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)

		previous = &ChainEntry{
			cert,
			key,
		}
	}

	return chain
}
