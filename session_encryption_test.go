package mdoc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestSK_Equality(t *testing.T) {
	eReaderKey, err := GenerateESessionPrivateKey(rand.Reader, ecdh.P256())
	if err != nil {
		t.Fatal(err)
	}

	eDeviceKey, err := GenerateESessionPrivateKey(rand.Reader, ecdh.P256())
	if err != nil {
		t.Fatal(err)
	}

	sessionTranscriptBytes := []byte{1, 2, 3, 4}

	{
		readerSKReader, err := SKReader(eReaderKey, eDeviceKey.PublicKey(), sessionTranscriptBytes)
		if err != nil {
			t.Fatal(err)
		}

		deviceSKReader, err := SKReader(eDeviceKey, eReaderKey.PublicKey(), sessionTranscriptBytes)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(readerSKReader, deviceSKReader) {
			t.Fatal()
		}
	}

	{
		readerSKDevice, err := SKDevice(eReaderKey, eDeviceKey.PublicKey(), sessionTranscriptBytes)
		if err != nil {
			t.Fatal(err)
		}

		deviceSKDevice, err := SKDevice(eDeviceKey, eReaderKey.PublicKey(), sessionTranscriptBytes)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(readerSKDevice, deviceSKDevice) {
			t.Fatal()
		}
	}
}

func TestSessionEncryption_RoundTrip(t *testing.T) {
	keySize := 256 / 8

	skReader := make([]byte, keySize)
	skDevice := make([]byte, keySize)

	for i := range keySize {
		skReader[i] = byte(i)
		skDevice[i] = byte(keySize - i)
	}

	readerSessionEncryption, err := NewReaderSessionEncryption(skReader, skDevice)
	if err != nil {
		t.Fatal(err)
	}

	deviceSessionEncryption, err := NewDeviceSessionEncryption(skDevice, skReader)
	if err != nil {
		t.Fatal(err)
	}

	clearText := []byte("lorem ipsum")

	readerCipherText1 := readerSessionEncryption.Encrypt(clearText)
	deviceClearText1, err := deviceSessionEncryption.Decrypt(readerCipherText1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clearText, deviceClearText1) {
		t.Fatal()
	}

	deviceCipherText1 := deviceSessionEncryption.Encrypt(clearText)
	readerClearText1, err := readerSessionEncryption.Decrypt(deviceCipherText1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clearText, readerClearText1) {
		t.Fatal()
	}

	readerCipherText2 := readerSessionEncryption.Encrypt(clearText)
	deviceClearText2, err := deviceSessionEncryption.Decrypt(readerCipherText2)
	if err != nil {
		t.Fatal()
	}
	if !bytes.Equal(clearText, deviceClearText2) {
		t.Fatal()
	}
	if bytes.Equal(readerCipherText1, readerCipherText2) {
		t.Fatal()
	}

	deviceCipherText2 := deviceSessionEncryption.Encrypt(clearText)
	readerClearText2, err := readerSessionEncryption.Decrypt(deviceCipherText2)
	if err != nil {
		t.Fatal()
	}
	if !bytes.Equal(clearText, readerClearText2) {
		t.Fatal()
	}
	if bytes.Equal(deviceCipherText1, deviceCipherText2) {
		t.Fatal()
	}
}
