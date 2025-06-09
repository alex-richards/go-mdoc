package cbor

import (
	"errors"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

var (
	ErrUnsupportedValue = errors.New("mdoc: cbor: unsupported value")
	ErrUnknownType      = errors.New("mdoc: cbor: unknown type")
)

type CBORType string

const (
	CBORTypeTstr     CBORType = "tstr"
	CBORTypeBstr     CBORType = "bstr"
	CBORTypeTdate    CBORType = "tdate"
	CBORTypeFullDate CBORType = "full-date"
	CBORTypeUint     CBORType = "uint"
	CBORTypeBool     CBORType = "bool"
)

func MarshalTypedValue(cborType CBORType, value any) ([]byte, error) {
	switch cborType {
	case CBORTypeTstr:
		_, ok := value.(string)
		if ok {
			return cbor.Marshal(value)
		}
		return nil, ErrUnsupportedValue

	case CBORTypeBstr:
		_, ok := value.([]byte)
		if ok {
			return cbor.Marshal(value)
		}
		return nil, ErrUnsupportedValue

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
		return nil, ErrUnsupportedValue

	case CBORTypeBool:
		_, ok := value.(bool)
		if ok {
			return cbor.Marshal(value)
		}
		return nil, ErrUnsupportedValue

	case CBORTypeTdate:
		switch datetime := value.(type) {
		case time.Time, *time.Time:
			// TODO configure marshaller
			return cbor.Marshal(datetime)
		}
		return nil, ErrUnsupportedValue

	case CBORTypeFullDate:
		switch datetime := value.(type) {
		case time.Time, *time.Time:
			// TODO configure marshaller
			return cbor.Marshal(datetime)
		}
		return nil, ErrUnsupportedValue
	}

	return nil, ErrUnknownType
}
