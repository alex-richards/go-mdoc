package mdoc

import (
	"bytes"
	"testing"
)

func TestCipherSuite_KeyConversions_RoundTrip(t *testing.T) {
	rand := DeterministicRand{1, 2, 3, 4}

	privateKey := NewTestECDHKey(t, rand)

	coseKey, err := CipherSuite1.ECDHToCOSE(privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := CipherSuite1.COSEToECDH(coseKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(privateKey.PublicKey().Bytes(), publicKey.Bytes()) {
		t.Fatal()
	}
}
