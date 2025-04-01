package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func Test_NewIACACertificate(t *testing.T) {
	rand := NewDeterministicRand()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		t.Fatal(err)
	}

	der, err := NewIACACertificate(
		rand,
		private,
		private.Public(),
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

	err = validateIACARootCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}

	privateDS, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		t.Fatal(err)
	}

	derDS, err := NewDocumentSignerCertificate(
		rand,
		private,
		cert,
		privateDS.Public(),
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

	err = validateDocumentSignerCertificate(certDS, cert)
	if err != nil {
		t.Fatal(err)
	}
}
