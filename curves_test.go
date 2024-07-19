package mdoc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestKeyConversions(t *testing.T) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	coseKey, err := NewCOSEKeyFromECDHPublicKey(*privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := NewECDHPublicKeyFromCOSEKey(*coseKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(privateKey.PublicKey().Bytes(), publicKey.Bytes()) {
		t.Fail()
	}
}
