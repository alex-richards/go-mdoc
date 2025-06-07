package spec

import (
	"bytes"
	"testing"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/cipher_suite/ecdh"
	"github.com/alex-richards/go-mdoc/holder"
	"github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/alex-richards/go-mdoc/internal/testutil"
	"github.com/alex-richards/go-mdoc/reader"
	"github.com/alex-richards/go-mdoc/session"
)

func Test_SK_Equality(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)

	eReaderKey, err := ecdh.GeneratePrivateKey(rand, mdoc.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	eDeviceKey, err := ecdh.GeneratePrivateKey(rand, mdoc.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	sessionTranscriptBytes := []byte{1, 2, 3, 4}

	{
		readerSKReader, err := session.SKReader(eReaderKey.Agreer, &eDeviceKey.PublicKey, sessionTranscriptBytes)
		if err != nil {
			t.Fatal(err)
		}

		deviceSKReader, err := session.SKReader(eDeviceKey.Agreer, &eReaderKey.PublicKey, sessionTranscriptBytes)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(readerSKReader, deviceSKReader) {
			t.Fatal()
		}
	}

	{
		readerSKDevice, err := session.SKDevice(eReaderKey.Agreer, &eDeviceKey.PublicKey, sessionTranscriptBytes)
		if err != nil {
			t.Fatal(err)
		}

		deviceSKDevice, err := session.SKDevice(eDeviceKey.Agreer, &eReaderKey.PublicKey, sessionTranscriptBytes)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(readerSKDevice, deviceSKDevice) {
			t.Fatal()
		}
	}
}

func Test_SessionEncryption_RoundTrip(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)

	eDeviceKey, err := ecdh.GeneratePrivateKey(rand, mdoc.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	eReaderKey, err := ecdh.GeneratePrivateKey(rand, mdoc.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	sessionTranscriptBytes, err := cbor.NewTaggedEncodedCBOR([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}

	readerSessionEncryption, err := reader.NewSessionEncryption(eReaderKey, &eDeviceKey.PublicKey, sessionTranscriptBytes)
	if err != nil {
		t.Fatal(err)
	}

	deviceSessionEncryption, err := holder.NewSessionEncryption(eDeviceKey, &eReaderKey.PublicKey, sessionTranscriptBytes)
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
