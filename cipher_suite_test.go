package mdoc

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

func TestCipherSuite_KeyConversions_RoundTrip(t *testing.T) {
	rand := DeterministicRand{1, 2, 3, 4}

	testKeyECDH := NewTestECDHKey(t, rand)

	tests := []struct {
		name      string
		key       *ecdh.PublicKey
		transform func(key *ecdh.PublicKey) (*ecdh.PublicKey, error)
	}{
		{
			name: "ECDH to COSE to ECDH",
			key:  testKeyECDH.PublicKey(),
			transform: func(key *ecdh.PublicKey) (*ecdh.PublicKey, error) {
				keyCOSE, err := CipherSuite1.ecdhToCOSE(key)
				if err != nil {
					return nil, err
				}

				keyECDH, err := CipherSuite1.coseToECDH(keyCOSE)
				if err != nil {
					return nil, err
				}

				return keyECDH, nil
			},
		},
		{
			name: "ECDH to COSE to ECDSA to COSE to ECDH",
			key:  testKeyECDH.PublicKey(),
			transform: func(key *ecdh.PublicKey) (*ecdh.PublicKey, error) {
				keyCOSE, err := CipherSuite1.ecdhToCOSE(key)
				if err != nil {
					return nil, err
				}

				keyECDSA, err := CipherSuite1.coseToECDSA(keyCOSE)
				if err != nil {
					return nil, err
				}

				keyCOSE2, err := CipherSuite1.ecdsaToCOSE(keyECDSA)
				if err != nil {
					return nil, err
				}

				keyECDH, err := CipherSuite1.coseToECDH(keyCOSE2)
				if err != nil {
					return nil, err
				}

				return keyECDH, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.transform(tt.key)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(tt.key.Bytes(), got.Bytes()) {
				t.Fatalf(
					"want = %s, got = %s",
					hex.EncodeToString(tt.key.Bytes()),
					hex.EncodeToString(got.Bytes()),
				)
			}
		})
	}
}
