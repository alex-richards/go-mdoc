package mdoc

import (
	"errors"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

const (
	cborMajorTypeFloatNoContent = 7 << 5
)

const (
	cborNull = cborMajorTypeFloatNoContent | 22
)

const (
	cborTagEncodedCBOR = 24
)

var (
	ErrEmptyTaggedValue = errors.New("empty tagged value")
)

var (
	encodeModeTaggedEncodedCBOR cbor.EncMode
	decodeModeTaggedEncodedCBOR cbor.DecMode
)

func init() {
	ts := cbor.NewTagSet()
	err := ts.Add(
		cbor.TagOptions{DecTag: cbor.DecTagRequired, EncTag: cbor.EncTagRequired},
		reflect.TypeOf(bstr(nil)),
		cborTagEncodedCBOR,
	)
	if err != nil {
		panic(err)
	}

	encodeModeTaggedEncodedCBOR, err = cbor.EncOptions{}.EncModeWithTags(ts)
	if err != nil {
		panic(err)
	}

	decodeModeTaggedEncodedCBOR, err = cbor.DecOptions{}.DecModeWithTags(ts)
	if err != nil {
		panic(err)
	}
}

type bstr []byte

type TaggedEncodedCBOR struct {
	TaggedValue   bstr
	UntaggedValue bstr
}

func MarshalToNewTaggedEncodedCBOR(value any) (*TaggedEncodedCBOR, error) {
	untaggedValue, err := cbor.Marshal(value)
	if err != nil {
		return nil, err
	}

	return NewTaggedEncodedCBOR(untaggedValue)
}

func NewTaggedEncodedCBOR(untaggedValue []byte) (*TaggedEncodedCBOR, error) {
	taggedValue, err := encodeModeTaggedEncodedCBOR.Marshal((bstr)(untaggedValue))
	if err != nil {
		return nil, err
	}

	lenTagged := len(taggedValue)
	lenUntagged := len(untaggedValue)
	lenHeader := lenTagged - lenUntagged
	if lenHeader < 2 {
		panic("TODO")
	}

	return &TaggedEncodedCBOR{
		TaggedValue:   taggedValue,
		UntaggedValue: taggedValue[lenHeader-1:],
	}, nil
}

func (tec *TaggedEncodedCBOR) MarshalCBOR() ([]byte, error) {
	if tec.TaggedValue == nil {
		return nil, ErrEmptyTaggedValue
	}
	return tec.TaggedValue, nil
}

func (tec *TaggedEncodedCBOR) UnmarshalCBOR(taggedValue []byte) error {
	var untaggedValue bstr
	if err := decodeModeTaggedEncodedCBOR.Unmarshal(taggedValue, &untaggedValue); err != nil {
		return err
	}

	tec.TaggedValue = taggedValue
	tec.UntaggedValue = untaggedValue

	return nil
}
