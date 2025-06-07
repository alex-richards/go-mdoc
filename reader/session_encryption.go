package reader

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/alex-richards/go-mdoc/session"
)

func NewSessionEncryption(
	eReaderKey *mdoc.PrivateKey,
	eDeviceKey *mdoc.PublicKey,
	sessionTranscriptBytes *cbor.TaggedEncodedCBOR,
) (*session.SessionEncryption, error) {
	skReader, err := session.SKReader(eReaderKey.Agreer, eDeviceKey, sessionTranscriptBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	skDevice, err := session.SKDevice(eReaderKey.Agreer, eDeviceKey, sessionTranscriptBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	return session.NewSessionEncryption(
		skReader,
		session.ReaderIdentifier,
		skDevice,
		session.DeviceIdentifier,
	)
}
