package mdoc

import (
	"github.com/fxamacker/cbor/v2"
)

type SessionEstablishment struct {
	EReaderKeyBytes TaggedEncodedCBOR `cbor:"eReaderKey"`
	Data            []byte            `cbor:"data"`
}

func NewSessionEstablishment(eReaderKey *PublicKey, data []byte) (*SessionEstablishment, error) {
	eReaderKeyBytes, err := MarshalToNewTaggedEncodedCBOR(eReaderKey)
	if err != nil {
		return nil, err
	}

	return &SessionEstablishment{
		EReaderKeyBytes: *eReaderKeyBytes,
		Data:            data,
	}, nil
}

func (se *SessionEstablishment) EReaderKey() (*PublicKey, error) {
	eReaderKey := new(PublicKey)
	if err := cbor.Unmarshal(se.EReaderKeyBytes.UntaggedValue, eReaderKey); err != nil {
		return nil, err
	}

	return eReaderKey, nil
}

type SessionData struct {
	Data   []byte        `cbor:"data"`
	Status SessionStatus `cbor:"status"`
}

type SessionStatus uint

const (
	SessionStatusErrorSessionEncryption SessionStatus = 10
	SessionStatusErrorCBORDecoding      SessionStatus = 11
	SessionStatusSessionTermination     SessionStatus = 20
)
