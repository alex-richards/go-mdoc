package mdoc

import (
	"errors"

	"github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/alex-richards/go-mdoc/util"
)

var (
	ErrUnrecognisedRetrievalMethod = errors.New("mdoc: unrecognized retrieval method")
)

const (
	DeviceEngagementVersion = "1.0"
)

type DeviceEngagement struct {
	Version                string                  `cbor:"0,keyasint"`
	Security               Security                `cbor:"1,keyasint"`
	DeviceRetrievalMethods []DeviceRetrievalMethod `cbor:"2,keyasint,omitempty"`
	ServerRetrievalMethods []any                   `cbor:"3,keyasint,omitempty"` // TODO
	ProtocolInfo           any                     `cbor:"4,keyasint,omitempty"` // TODO
}

func NewDeviceEngagementBLE(
	eDeviceKey *PublicKey,
	centralClientUUID, peripheralServerUUID *util.UUID,
) (*DeviceEngagement, error) {
	eDeviceKeyBytes, err := cbor.MarshalToNewTaggedEncodedCBOR(eDeviceKey)
	if err != nil {
		return nil, err
	}

	return &DeviceEngagement{
		DeviceEngagementVersion,
		Security{
			CipherSuiteIdentifier: CipherSuiteVersion,
			EDeviceKeyBytes:       *eDeviceKeyBytes,
		},
		[]DeviceRetrievalMethod{
			{
				Type:    DeviceRetrievalMethodTypeBLE,
				Version: DeviceRetrievalVersion,
				RetrievalOptions: BLEOptions{
					SupportsCentralClient:    centralClientUUID != nil,
					CentralClientUUID:        centralClientUUID,
					SupportsPeripheralServer: peripheralServerUUID != nil,
					PeripheralServerUUID:     peripheralServerUUID,
				},
			},
		},
		nil,
		nil,
	}, nil
}

type Security struct {
	_                     struct{} `cbor:",toarray"`
	CipherSuiteIdentifier int
	EDeviceKeyBytes       cbor.TaggedEncodedCBOR
}

type DeviceRetrievalMethodType uint

const (
	DeviceRetrievalMethodTypeNFC       DeviceRetrievalMethodType = 1
	DeviceRetrievalMethodTypeBLE       DeviceRetrievalMethodType = 2
	DeviceRetrievalMethodTypeWiFiAware DeviceRetrievalMethodType = 3
)

const DeviceRetrievalVersion = 1

type DeviceRetrievalMethod struct {
	Type             DeviceRetrievalMethodType
	Version          uint
	RetrievalOptions RetrievalOptions
}

type RetrievalOptions any

type WifiOptions struct {
	PassPhraseInfoPassPhrase  string `cbor:"0,keyasint,omitempty"`
	ChannelInfoOperatingClass uint   `cbor:"1,keyasint,omitempty"`
	ChannelInfoChannelNumber  uint   `cbor:"2,keyasint,omitempty"`
	BandInfoSupportedBands    []byte `cbor:"3,keyasint,omitempty"`
}

type BLEAddress [6]byte

type BLEOptions struct {
	SupportsPeripheralServer      bool        `cbor:"0,keyasint"`
	SupportsCentralClient         bool        `cbor:"1,keyasint"`
	PeripheralServerUUID          *util.UUID  `cbor:"10,keyasint,omitempty"`
	CentralClientUUID             *util.UUID  `cbor:"11,keyasint,omitempty"`
	PeripheralServerDeviceAddress *BLEAddress `cbor:"20,keyasint,omitempty"`
}

type NFCOptions struct {
	MaxLengthCommandData  uint `cbor:"0,keyasint"`
	MaxLengthResponseData uint `cbor:"1,keyasint"`
}
