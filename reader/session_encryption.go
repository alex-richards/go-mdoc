package reader

import "github.com/alex-richards/go-mdoc"

func NewSessionEncryption(
	eReaderKey PrivateEReaderKey,
	eDeviceKey *mdoc.PublicKey,
	sessionTranscriptBytes *mdoc.TaggedEncodedCBOR,
) (*mdoc.SessionEncryption, error) {
	skReader, err := mdoc.SKReader(eReaderKey.Agreer(), eDeviceKey, sessionTranscriptBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	skDevice, err := mdoc.SKDevice(eReaderKey.Agreer(), eDeviceKey, sessionTranscriptBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	return mdoc.NewSessionEncryption(
		skReader,
		mdoc.ReaderIdentifier,
		skDevice,
		mdoc.DeviceIdentifier,
	)
}
