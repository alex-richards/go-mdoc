package session

import (
	"github.com/alex-richards/go-mdoc"
	mdoccbor "github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/fxamacker/cbor/v2"
)

type SessionEstablishment struct {
	EReaderKeyBytes mdoccbor.TaggedEncodedCBOR `cbor:"eReaderKey"`
	Data            []byte                     `cbor:"data"`
}

func NewSessionEstablishment(eReaderKey *mdoc.PublicKey, data []byte) (*SessionEstablishment, error) {
	eReaderKeyBytes, err := mdoccbor.MarshalToNewTaggedEncodedCBOR(eReaderKey)
	if err != nil {
		return nil, err
	}

	return &SessionEstablishment{
		EReaderKeyBytes: *eReaderKeyBytes,
		Data:            data,
	}, nil
}

func (se *SessionEstablishment) EReaderKey() (*mdoc.PublicKey, error) {
	eReaderKey := new(mdoc.PublicKey)
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
