package mdoc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
)

type TestStruct struct {
	One int
	Two string
}

func TestEncodedCBORTagged(t *testing.T) {
	testStruct := TestStruct{
		One: 1,
		Two: "2",
	}

	testStructBytes, err := cbor.Marshal(testStruct)
	if err != nil {
		t.Fatal(err)
	}

	if errUntagged := cbor.Unmarshal(testStructBytes, &TaggedEncodedCBOR{}); errUntagged == nil {
		t.Fatal("expected error")
	}

	taggedEncodedCBOR, err := NewTaggedEncodedCBOR(testStructBytes)
	if err != nil {
		t.Fatal(err)
	}

	testStructBytesTagged, err := cbor.Marshal(taggedEncodedCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(testStructBytesTagged[0:2], []byte{0xd8, TagEncodedCBOR}) {
		t.Fatal(hex.EncodeToString(testStructBytesTagged))
	}

	var taggedEncodedCBORUnmarshalled TaggedEncodedCBOR
	if err = cbor.Unmarshal(testStructBytesTagged, &taggedEncodedCBORUnmarshalled); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(testStructBytes, []byte(taggedEncodedCBORUnmarshalled.untaggedValue)); diff != "" {
		t.Fatal(diff)
	}
}
