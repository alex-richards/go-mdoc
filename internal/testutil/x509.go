package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"
)

type ChainEntry struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func NewCA(t testing.TB, rand io.Reader, template x509.Certificate) *ChainEntry {
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

func NewChain(t testing.TB, rand io.Reader, ca *ChainEntry, len int) []*x509.Certificate {
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
			Issuer:                previous.Cert.Subject,
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
			previous.Cert,
			key.Public(),
			previous.Key,
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
