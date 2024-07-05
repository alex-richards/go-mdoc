package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
)

type TestStruct struct {
    One int
    Two string
}

func TestEncodedCBORTagged(t *testing.T){
    testStruct := TestStruct {
        One: 1,
        Two: "2",
    }

    testStructBytes, err := cbor.Marshal(testStruct)
    if err != nil {
        t.Fatal(err)
    }

    err = cbor.Unmarshal(testStructBytes, TaggedEncodedCBOR{})
    if err == nil {
        t.Fatal()
    }

    testStructBytesTagged, err := cbor.Marshal((TaggedEncodedCBOR)(testStructBytes))
    if err != nil {
        t.Fatal(err)
    }

    testStructBytesUntagged := make([]byte, 0)
    err = cbor.Unmarshal(testStructBytesTagged, (*TaggedEncodedCBOR)(&testStructBytesUntagged))
    if err != nil {
        t.Fatal(err)
    }

    if diff := cmp.Diff(testStructBytes, testStructBytesUntagged); diff != "" {
        t.Fatal(diff)
    }
}

