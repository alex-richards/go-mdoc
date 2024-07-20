package mdoc

import (
	"errors"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

const TagEncodedCBOR = 24

type bstr []byte
type TaggedEncodedCBOR struct {
	taggedValue   bstr
	untaggedValue bstr
}

var (
	encodeModeTaggedEncodedCBOR cbor.EncMode
	decodeModeTaggedEncodedCBOR cbor.DecMode
)

var (
	ErrorEmptyTaggedValue   = errors.New("empty tagged value")
	ErrorEmptyUntaggedValue = errors.New("empty untagged value")
)

func init() {
	ts := cbor.NewTagSet()
	ts.Add(
		cbor.TagOptions{DecTag: cbor.DecTagRequired, EncTag: cbor.EncTagRequired},
		reflect.TypeOf(bstr(nil)),
		TagEncodedCBOR,
	)

	var err error

	encodeModeTaggedEncodedCBOR, err = cbor.EncOptions{}.EncModeWithTags(ts)
	if err != nil {
		panic(err)
	}

	decodeModeTaggedEncodedCBOR, err = cbor.DecOptions{}.DecModeWithTags(ts)
	if err != nil {
		panic(err)
	}
}

func (tec *TaggedEncodedCBOR) TaggedValue() ([]byte, error) {
	if tec.taggedValue != nil {
		return tec.taggedValue, nil
	}

	if tec.untaggedValue != nil {
		return encodeModeTaggedEncodedCBOR.Marshal(tec.untaggedValue)
	}

	return nil, ErrorEmptyTaggedValue
}

func (tec *TaggedEncodedCBOR) UntaggedValue() ([]byte, error) {
	if tec.untaggedValue != nil {
		return tec.untaggedValue, nil
	}

	if tec.taggedValue != nil {
		var untaggedValue []byte
		if err := decodeModeTaggedEncodedCBOR.Unmarshal(tec.taggedValue, untaggedValue); err != nil {
			return nil, err
		}

		return untaggedValue, nil
	}

	return nil, ErrorEmptyUntaggedValue
}

func (tec *TaggedEncodedCBOR) MarshalCBOR() ([]byte, error) {
	return tec.TaggedValue()
}

func (tec *TaggedEncodedCBOR) UnmarshalCBOR(taggedValue []byte) error {
	var untaggedValue []byte
	err := decodeModeTaggedEncodedCBOR.Unmarshal(taggedValue, &untaggedValue)
	if err != nil {
		return err
	}

	tec.taggedValue = taggedValue
	tec.untaggedValue = untaggedValue
	return nil
}

func NewTaggedEncodedCBOR(untaggedValue []byte) (*TaggedEncodedCBOR, error) {
	taggedEncodedCBOR := TaggedEncodedCBOR{
		untaggedValue: untaggedValue,
	}

	var err error
	taggedEncodedCBOR.taggedValue, err = taggedEncodedCBOR.TaggedValue()
	if err != nil {
		return nil, err
	}

	return &taggedEncodedCBOR, nil
}
