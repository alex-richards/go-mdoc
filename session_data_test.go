package mdoc

import (
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
)

func TestNewSessionEstablishment(t *testing.T) {
	sessionEstablishment, err := NewSessionEstablishment(
		EReaderKeyPublic,
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
	eReaderKeyBytes, err := NewTaggedEncodedCBOR([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}

	sessionEstablishment := SessionEstablishment{
		EReaderKeyBytes: *eReaderKeyBytes,
		Data:            []byte{5, 6, 7, 8},
	}

	sessionEstablishmentBytes, err := cbor.Marshal(&sessionEstablishment)
	if err != nil {
		t.Fatal(err)
	}

	var sessionEstablishmentUnmarshalled SessionEstablishment
	if err = cbor.Unmarshal(sessionEstablishmentBytes, &sessionEstablishmentUnmarshalled); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		sessionEstablishment,
		sessionEstablishmentUnmarshalled,
		cmp.FilterPath(func(p cmp.Path) bool {
			return p.Last().Type() == reflect.TypeOf(TaggedEncodedCBOR{})
		}, cmp.Ignore()),
	); diff != "" {
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
