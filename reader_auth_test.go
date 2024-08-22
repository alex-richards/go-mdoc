package mdoc

import (
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestReaderAuth_Verify(t *testing.T) {
	// TODO unhappy path tests

	readerRootEncoded, err := hex.DecodeString(ReaderRootHex)
	if err != nil {
		t.Fatal(err)
	}

	readerRoot, err := x509.ParseCertificate(readerRootEncoded)
	if err != nil {
		t.Fatal(err)
	}

	sessionTranscriptTagged, err := hex.DecodeString(SessionTranscriptHex)
	if err != nil {
		t.Fatal(err)
	}

	var sessionTranscriptBytes TaggedEncodedCBOR
	err = cbor.Unmarshal(sessionTranscriptTagged, &sessionTranscriptBytes)
	if err != nil {
		t.Fatal(err)
	}

	var sessionTranscript SessionTranscript
	err = cbor.Unmarshal(sessionTranscriptBytes.UntaggedValue, &sessionTranscript)
	if err != nil {
		t.Fatal(err)
	}

	deviceRequestBytes, err := hex.DecodeString(DeviceRequestHex)
	if err != nil {
		t.Fatal(err)
	}

	var deviceRequest DeviceRequest
	if err := cbor.Unmarshal(deviceRequestBytes, &deviceRequest); err != nil {
		t.Fatal(err)
	}

	now, err := time.Parse(time.RFC3339, "2021-01-02T15:04:05Z")
	if err != nil {
		t.Fatal(err)
	}

	for _, docRequest := range deviceRequest.DocRequests {
		readerAuthentication := NewReaderAuthentication(
			sessionTranscript,
			docRequest.ItemsRequestBytes,
		)

		readerAuthenticationUntagged, err := cbor.Marshal(&readerAuthentication)
		if err != nil {
			t.Fatal(err)
		}

		readerAuthenticationBytes, err := NewTaggedEncodedCBOR(readerAuthenticationUntagged)
		if err != nil {
			t.Fatal(err)
		}

		err = docRequest.ReaderAuth.Verify(readerAuthenticationBytes, []*x509.Certificate{readerRoot}, now)
		if err != nil {
			t.Fatal(err)
		}
	}
}
