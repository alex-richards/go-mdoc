package mdoc

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	SessionStatusErrorSessionEncryption uint = 10
	SessionStatusErrorCBORDecoding      uint = 11
	SessionStatusSessionTermination     uint = 20
)

type SessionEstablishment struct {
	EReaderKeyBytes TaggedEncodedCBOR `cbor:"eReaderKey"`
	Data            []byte            `cbor:"data"`
}

func NewSessionEstablishment(eReaderKey *cose.Key, data []byte) (*SessionEstablishment, error) {
	eReaderKeyBytes, err := cbor.Marshal(eReaderKey)
	if err != nil {
		return nil, err
	}

	return &SessionEstablishment{
		EReaderKeyBytes: eReaderKeyBytes,
		Data:            data,
	}, nil
}

type SessionData struct {
	Data   []byte `cbor:"data"`
	Status uint   `cbor:"status"`
}

func (se *SessionEstablishment) EReaderKey() (*cose.Key, error) {
	eReaderKey := new(cose.Key)
	if err := cbor.Unmarshal(se.EReaderKeyBytes, eReaderKey); err != nil {
		return nil, err
	}
	return eReaderKey, nil
}
