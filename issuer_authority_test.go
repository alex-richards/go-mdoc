package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func Test_Certificates(t *testing.T) {
	rand := NewDeterministicRand()

	iacaCurves := []Curve{
		CurveP256,
		CurveP384,
		CurveP521,
	}

	documentSignerCurves := []Curve{
		CurveP256,
		CurveP384,
		CurveP521,
		CurveEd25519,
	}

	for _, iacaCurve := range iacaCurves {
		for _, documentSignerCurve := range documentSignerCurves {
			t.Run(fmt.Sprintf("IACA %s - Document Signer %s", iacaCurve.Name(), documentSignerCurve.Name()), func(t *testing.T) {
				var err error
				var iacaPrivate crypto.Signer
				var iacaPublic crypto.PublicKey
				switch iacaCurve {
				case CurveP256:
					iacaPrivate, err = ecdsa.GenerateKey(elliptic.P256(), rand)
					iacaPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case CurveP384:
					iacaPrivate, err = ecdsa.GenerateKey(elliptic.P384(), rand)
					iacaPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case CurveP521:
					iacaPrivate, err = ecdsa.GenerateKey(elliptic.P521(), rand)
					iacaPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				default:
					t.Fatal("Unknown Curve")
				}

				der, err := NewIACACertificate(
					rand,
					iacaPrivate,
					iacaPublic,
					*big.NewInt(1234),
					"Test IACA",
					"NZ",
					nil,
					time.UnixMilli(1000),
					time.UnixMilli(2000),
				)
				if err != nil {
					t.Fatal(err)
				}

				cert, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}

				err = ValidateIACACertificate(cert)
				if err != nil {
					t.Fatal(err)
				}

				var dsPrivate crypto.Signer
				var dsPublic crypto.PublicKey
				switch iacaCurve {
				case CurveP256:
					dsPrivate, err = ecdsa.GenerateKey(elliptic.P256(), rand)
					dsPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case CurveP384:
					dsPrivate, err = ecdsa.GenerateKey(elliptic.P384(), rand)
					dsPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case CurveP521:
					dsPrivate, err = ecdsa.GenerateKey(elliptic.P224(), rand)
					dsPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case CurveEd25519:
					dsPublic, dsPrivate, err = ed25519.GenerateKey(rand)
				default:
					t.Fatal("Unknown Curve")
				}
				_ = dsPrivate

				derDS, err := NewDocumentSignerCertificate(
					rand,
					iacaPrivate,
					cert,
					dsPublic,
					*big.NewInt(5678),
					"Test Document Signer",
					nil,
					time.UnixMilli(1000),
					time.UnixMilli(2000),
				)
				if err != nil {
					t.Fatal(err)
				}

				certDS, err := x509.ParseCertificate(derDS)
				if err != nil {
					t.Fatal(err)
				}

				err = ValidateDocumentSignerCertificate(certDS, cert)
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
