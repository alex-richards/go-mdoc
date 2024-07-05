package mdoc

import (
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

const TagEncodedCBOR = 24

type TaggedEncodedCBOR []byte
type taggedEncodedCBOR []byte

var (
    encodeModeTaggedEncodedCBOR cbor.EncMode
    decodeModeTaggedEncodedCBOR cbor.DecMode
)

func init(){
    ts := cbor.NewTagSet()
    ts.Add(
        cbor.TagOptions{DecTag: cbor.DecTagRequired, EncTag: cbor.EncTagRequired},
        reflect.TypeOf(taggedEncodedCBOR{}),
        TagEncodedCBOR,
    )

    var err error

    encodeModeTaggedEncodedCBOR, err = cbor.EncOptions{}.EncModeWithTags(ts)
    if err != nil {
        panic(err)
    }

    decodeModeTaggedEncodedCBOR, err = cbor.DecOptions{}.DecModeWithTags(ts)
    if  err != nil {
        panic(err)
    }
}

func (ec *TaggedEncodedCBOR) MarshalCBOR() ([]byte, error) {
    return encodeModeTaggedEncodedCBOR.Marshal((*taggedEncodedCBOR)(ec))
}

func (ec *TaggedEncodedCBOR) UnmarshalCBOR(data []byte) error{
    return decodeModeTaggedEncodedCBOR.Unmarshal(data, (*taggedEncodedCBOR)(ec))
}

