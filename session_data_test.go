package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
)

func TestNewSessionEstablishment(t *testing.T) {
	sessionEstablishment, err := NewSessionEstablishment(
		EReaderKey,
		[]byte{1, 2, 3, 4},
	)
	if err != nil {
		t.Fatal(err)
	}

	if sessionEstablishment == nil {
		t.Fatal()
	}
}

func TestSessionEstablishmentCBORRoundTrip(t *testing.T) {
	sessionEstablishment := &SessionEstablishment{
		EReaderKeyBytes: []byte{1, 2, 3, 4},
		Data:            []byte{5, 6, 7, 8},
	}

	sessionEstablishmentBytes, err := cbor.Marshal(sessionEstablishment)
	if err != nil {
		t.Fatal(err)
	}

	sessionEstablishmentUnmarshalled := new(SessionEstablishment)
	if err = cbor.Unmarshal(sessionEstablishmentBytes, sessionEstablishmentUnmarshalled); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(sessionEstablishment, sessionEstablishmentUnmarshalled); diff != "" {
		t.Fatal(diff)
	}
}

func TestSessionDataCBORRoundTrip(t *testing.T) {
	sessionData := &SessionData{
		Data:   []byte{1, 2, 3, 4},
		Status: SessionStatusSessionTermination,
	}

	sessionDataBytes, err := cbor.Marshal(sessionData)
	if err != nil {
		t.Fatal(err)
	}

	sessionDataUnmarshalled := new(SessionData)
	if err = cbor.Unmarshal(sessionDataBytes, sessionDataUnmarshalled); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(sessionData, sessionDataUnmarshalled); diff != "" {
		t.Fatal(diff)
	}
}
