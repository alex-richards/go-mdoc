package mdoc

import (
	"errors"
	"math/big"
	"reflect"
	"time"

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

type CBORType string

const (
	CBORTypeTstr     CBORType = "tstr"
	CBORTypeBstr     CBORType = "bstr"
	CBORTypeTdate    CBORType = "tdate"
	CBORTypeFullDate CBORType = "full-date"
	CBORTypeUint     CBORType = "uint"
	CBORTypeBool     CBORType = "bool"
)

func marshalCBORTypedValue(cborType CBORType, value any) ([]byte, error) {
	switch cborType {
	case CBORTypeTstr:
		_, ok := value.(string)
		if ok {
			return cbor.Marshal(value)
		}

	case CBORTypeBstr:
		_, ok := value.([]byte)
		if ok {
			return cbor.Marshal(value)
		}

	case CBORTypeUint:
		supported := false
		switch v := value.(type) {
		case uint8, uint16, uint32, uint64:
			supported = true
		case int8:
			supported = v >= 0
		case int16:
			supported = v >= 0
		case int32:
			supported = v >= 0
		case int64:
			supported = v >= 0
		case *big.Int:
			supported = v.Sign() >= 0
		case big.Int:
			supported = v.Sign() >= 0
		}
		if supported {
			return cbor.Marshal(value)
		}

	case CBORTypeBool:
		_, ok := value.(bool)
		if ok {
			return cbor.Marshal(value)
		}

	case CBORTypeTdate:
		switch datetime := value.(type) {
		case time.Time, *time.Time:
			// TODO configure marshaller
			return cbor.Marshal(datetime)
		}

	case CBORTypeFullDate:
		switch datetime := value.(type) {
		case time.Time, *time.Time:
			// TODO configure marshaller
			return cbor.Marshal(datetime)
		}
	}

	return nil, nil // TODO error
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
