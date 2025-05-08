package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/internal/testutil"
	"math/big"
	"testing"
	"time"
)

func Test_Certificates(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)

	iacaCurves := []mdoc.Curve{
		mdoc.CurveP256,
		mdoc.CurveP384,
		mdoc.CurveP521,
	}

	documentSignerCurves := []mdoc.Curve{
		mdoc.CurveP256,
		mdoc.CurveP384,
		mdoc.CurveP521,
		mdoc.CurveEd25519,
	}

	for _, iacaCurve := range iacaCurves {
		for _, documentSignerCurve := range documentSignerCurves {
			t.Run(fmt.Sprintf("IACA %s - Document Signer %s", iacaCurve.Name(), documentSignerCurve.Name()), func(t *testing.T) {
				var err error
				var iacaPrivate crypto.Signer
				var iacaPublic crypto.PublicKey
				switch iacaCurve {
				case mdoc.CurveP256:
					iacaPrivate, err = ecdsa.GenerateKey(elliptic.P256(), rand)
					iacaPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case mdoc.CurveP384:
					iacaPrivate, err = ecdsa.GenerateKey(elliptic.P384(), rand)
					iacaPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case mdoc.CurveP521:
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

				err = mdoc.ValidateIACACertificate(cert)
				if err != nil {
					t.Fatal(err)
				}

				var dsPrivate crypto.Signer
				var dsPublic crypto.PublicKey
				switch iacaCurve {
				case mdoc.CurveP256:
					dsPrivate, err = ecdsa.GenerateKey(elliptic.P256(), rand)
					dsPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case mdoc.CurveP384:
					dsPrivate, err = ecdsa.GenerateKey(elliptic.P384(), rand)
					dsPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case mdoc.CurveP521:
					dsPrivate, err = ecdsa.GenerateKey(elliptic.P224(), rand)
					dsPublic = iacaPrivate.Public()
					if err != nil {
						t.Fatal(err)
					}
				case mdoc.CurveEd25519:
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

				err = mdoc.ValidateDocumentSignerCertificate(certDS, cert)
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
