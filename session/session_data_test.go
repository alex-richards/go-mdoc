package session

import (
	"reflect"
	"testing"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/cipher_suite/ecdsa"
	cbor2 "github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/alex-richards/go-mdoc/internal/testutil"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
)

func Test_NewSessionEstablishment(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)

	deviceKeyPrivate, err := ecdsa.GeneratePrivateKey(rand, mdoc.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewSessionEstablishment(
		&deviceKeyPrivate.PublicKey,
		[]byte{1, 2, 3, 4},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_SessionEstablishment_CBOR_RoundTrip(t *testing.T) {
	eReaderKeyBytes, err := cbor2.NewTaggedEncodedCBOR([]byte{1, 2, 3, 4})
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
		&sessionEstablishment,
		&sessionEstablishmentUnmarshalled,
		cmp.FilterPath(func(p cmp.Path) bool {
			return p.Last().Type() == reflect.TypeOf(cbor2.TaggedEncodedCBOR{})
		}, cmp.Ignore()),
	); diff != "" {
		t.Fatal(diff)
	}
}

func Test_SessionData_CBOR_RoundTrip(t *testing.T) {
	sessionData := SessionData{
		Data:   []byte{1, 2, 3, 4},
		Status: SessionStatusSessionTermination,
	}

	sessionDataBytes, err := cbor.Marshal(&sessionData)
	if err != nil {
		t.Fatal(err)
	}

	var sessionDataUnmarshalled SessionData
	if err = cbor.Unmarshal(sessionDataBytes, &sessionDataUnmarshalled); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(&sessionData, &sessionDataUnmarshalled); diff != "" {
		t.Fatal(diff)
	}
}
