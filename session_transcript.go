package mdoc

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
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
		err = errors.New("TODO")
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
	err := cbor.Unmarshal(data, &intermediateSessionTranscript)
	if err != nil {
		return err
	}

	st.DeviceEngagementBytes = intermediateSessionTranscript.DeviceEngagementBytes
	st.EReaderKeyBytes = intermediateSessionTranscript.EReaderKeyBytes

	{
		var qrHandover QRHandover
		err = cbor.Unmarshal(intermediateSessionTranscript.Handover, &qrHandover)
		if err == nil {
			st.Handover = qrHandover
			return nil
		}
	}

	{
		var nfcHandover NFCHandover
		err = cbor.Unmarshal(intermediateSessionTranscript.Handover, &nfcHandover)
		if err == nil {
			st.Handover = nfcHandover
			return nil
		}
	}

	return errors.New("TODO")
}

type Handover interface{}

type QRHandover struct{}

func (qrh *QRHandover) MarshalCBOR() ([]byte, error) {
	return []byte{22}, nil
}
func (qrh *QRHandover) UnmarshalCBOR(data []byte) error {
	if !bytes.Equal([]byte{22}, data) {
		return errors.New("TODO")
	}
	return nil
}

type NFCHandover struct {
	_               struct{} `cbor:",toarray"`
	HandoverSelect  []byte
	HandoverRequest []byte `cbor:",omitempty"`
}
