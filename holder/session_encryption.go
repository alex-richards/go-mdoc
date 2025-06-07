package holder

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/alex-richards/go-mdoc/session"
)

func NewSessionEncryption(
	eDeviceKey *mdoc.PrivateKey,
	eReaderKey *mdoc.PublicKey,
	sessionTranscriptBytes *cbor.TaggedEncodedCBOR,
) (*session.SessionEncryption, error) {
	skDevice, err := session.SKDevice(eDeviceKey.Agreer, eReaderKey, sessionTranscriptBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	skReader, err := session.SKReader(eDeviceKey.Agreer, eReaderKey, sessionTranscriptBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	return session.NewSessionEncryption(
		skDevice,
		session.DeviceIdentifier,
		skReader,
		session.ReaderIdentifier,
	)
}
