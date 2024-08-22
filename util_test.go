package mdoc

import (
	"crypto/ecdh"
	"github.com/veraison/go-cose"
	"io"
	"testing"
)

type DeterministicRand []byte

func (r DeterministicRand) Read(p []byte) (n int, err error) {
	write := len(p)
	wrote := 0
	for wrote < write {
		wrote += copy(p[wrote:], r)
	}
	return wrote, nil
}

func NewTestCOSEKey(t *testing.T, rand io.Reader) *cose.Key {
	t.Helper()

	s := 256 / 8

	x := make([]byte, s)
	_, err := rand.Read(x)
	if err != nil {
		t.Fatal(err)
	}

	y := make([]byte, s)
	_, err = rand.Read(y)
	if err != nil {
		t.Fatal(err)
	}

	key, err := cose.NewKeyEC2(cose.AlgorithmES256, x, y, nil)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func NewTestECDHKey(t *testing.T, rand io.Reader) *ecdh.PrivateKey {
	t.Helper()

	key, err := ecdh.P256().GenerateKey(rand)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
