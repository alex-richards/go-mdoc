package holder

import "github.com/alex-richards/go-mdoc"

func NewSessionEncryption(
	eDeviceKey PrivateEDeviceKey,
	eReaderKey *mdoc.PublicKey,
	sessionTranscriptBytes *mdoc.TaggedEncodedCBOR,
) (*mdoc.SessionEncryption, error) {
	skDevice, err := mdoc.SKDevice(eDeviceKey.Agreer(), eReaderKey, sessionTranscriptBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	skReader, err := mdoc.SKReader(eDeviceKey.Agreer(), eReaderKey, sessionTranscriptBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	return mdoc.NewSessionEncryption(
		skDevice,
		mdoc.DeviceIdentifier,
		skReader,
		mdoc.ReaderIdentifier,
	)
}
