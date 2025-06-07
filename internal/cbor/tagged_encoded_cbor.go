package cbor

import (
	"errors"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

const (
	majorTypeFloatNoContent = 7 << 5
)

const (
	Null = majorTypeFloatNoContent | 22
)

const (
	tagEncodedCBOR = 24
)

var (
	ErrEmptyTaggedValue   = errors.New("mdoc: cbor: empty tagged value")
	ErrEmptyUntaggedValue = errors.New("mdoc: cbor: empty untagged value")
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
		tagEncodedCBOR,
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
	if untaggedValue == nil {
		return nil, ErrEmptyUntaggedValue
	}

	taggedValue, err := encodeModeTaggedEncodedCBOR.Marshal((bstr)(untaggedValue))
	if err != nil {
		return nil, err
	}

	lenTagged := len(taggedValue)
	lenUntagged := len(untaggedValue)
	lenHeader := lenTagged - lenUntagged
	if lenHeader < 2 {
		panic("unexpected TaggedEncodedCBOR length")
	}

	return &TaggedEncodedCBOR{
		TaggedValue:   taggedValue,
		UntaggedValue: taggedValue[lenHeader:],
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
