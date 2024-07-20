package mdoc

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

var (
	ErrorUnreccognisedHandover = errors.New("unreccognised handover")
	errorNotQRHandover         = errors.New("not a qr handover")
)

type SessionTranscript struct {
	DeviceEngagementBytes TaggedEncodedCBOR
	EReaderKeyBytes       TaggedEncodedCBOR
	Handover              Handover
}

type intermediateSessionTranscript struct {
	_                     struct{} `cbor:",toarray"`
	DeviceEngagementBytes TaggedEncodedCBOR
	EReaderKeyBytes       TaggedEncodedCBOR
	Handover              cbor.RawMessage
}

func (st *SessionTranscript) MarshalCBOR() ([]byte, error) {
	var handoverBytes []byte
	var err error

	switch handover := st.Handover.(type) {
	case QRHandover:
		handoverBytes, err = cbor.Marshal(&handover)
	case NFCHandover:
		handoverBytes, err = cbor.Marshal(&handover)
	default:
		err = ErrorUnreccognisedHandover
	}

	if err != nil {
		return nil, err
	}

	intermediateSessionTranscript := intermediateSessionTranscript{
		DeviceEngagementBytes: st.DeviceEngagementBytes,
		EReaderKeyBytes:       st.EReaderKeyBytes,
		Handover:              handoverBytes,
	}

	return cbor.Marshal(&intermediateSessionTranscript)
}

func (st *SessionTranscript) UnmarshalCBOR(data []byte) error {
	var intermediateSessionTranscript intermediateSessionTranscript
	if err := cbor.Unmarshal(data, &intermediateSessionTranscript); err != nil {
		return err
	}

	{
		var qrHandover QRHandover
		if err := cbor.Unmarshal(intermediateSessionTranscript.Handover, &qrHandover); err == nil {
			st.DeviceEngagementBytes = intermediateSessionTranscript.DeviceEngagementBytes
			st.EReaderKeyBytes = intermediateSessionTranscript.EReaderKeyBytes
			st.Handover = qrHandover
			return nil
		}
	}

	{
		var nfcHandover NFCHandover
		if err := cbor.Unmarshal(intermediateSessionTranscript.Handover, &nfcHandover); err == nil {
			st.DeviceEngagementBytes = intermediateSessionTranscript.DeviceEngagementBytes
			st.EReaderKeyBytes = intermediateSessionTranscript.EReaderKeyBytes
			st.Handover = nfcHandover
			return nil
		}
	}

	return ErrorUnreccognisedHandover
}

type Handover interface{}

type QRHandover struct{}

func (qrh *QRHandover) MarshalCBOR() ([]byte, error) {
	return []byte{22}, nil
}
func (qrh *QRHandover) UnmarshalCBOR(data []byte) error {
	if !bytes.Equal([]byte{22}, data) {
		return errorNotQRHandover
	}
	return nil
}

type NFCHandover struct {
	_               struct{} `cbor:",toarray"`
	HandoverSelect  []byte
	HandoverRequest []byte `cbor:",omitempty"`
}
