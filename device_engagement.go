package mdoc

import (
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/veraison/go-cose"
)

var (
	ErrUnrecognisedRetrievalMethod = errors.New("unrecognized retrieval method")
)

type DeviceEngagement struct {
	Version                string                  `cbor:"0,keyasint"`
	Security               Security                `cbor:"1,keyasint"`
	DeviceRetrievalMethods []DeviceRetrievalMethod `cbor:"2,keyasint,omitempty"`
}

func NewDeviceEngagement(rand io.Reader, eDeviceKey *cose.Key) (*DeviceEngagement, error) {
	eDeviceKeyBytesUntagged, err := cbor.Marshal(eDeviceKey)
	if err != nil {
		return nil, err
	}

	eDeviceKeyBytes, err := NewTaggedEncodedCBOR(eDeviceKeyBytesUntagged)
	if err != nil {
		return nil, err
	}

	peripheralServerUUID, err := uuid.NewRandomFromReader(rand)
	if err != nil {
		return nil, err
	}
	centralClientUUID, err := uuid.NewRandomFromReader(rand)
	if err != nil {
		return nil, err
	}

	return &DeviceEngagement{
		"1.0",
		Security{
			CipherSuiteIdentifier: CipherSuite1.Version,
			EDeviceKeyBytes:       *eDeviceKeyBytes,
		},
		[]DeviceRetrievalMethod{
			{
				Type:    DeviceRetrievalMethodTypeBLE,
				Version: 1,
				RetrievalOptions: BLEOptions{
					SupportsPeripheralServer: true,
					SupportsCentralClient:    true,
					PeripheralServerUUID:     &peripheralServerUUID,
					CentralClientUUID:        &centralClientUUID,
				},
			},
		},
	}, nil
}

func (de *DeviceEngagement) EDeviceKey() (*cose.Key, error) {
	eDeviceKey := new(cose.Key)
	if err := cbor.Unmarshal(de.Security.EDeviceKeyBytes.UntaggedValue, eDeviceKey); err != nil {
		return nil, err
	}

	return eDeviceKey, nil
}

type Security struct {
	_                     struct{} `cbor:",toarray"`
	CipherSuiteIdentifier int
	EDeviceKeyBytes       TaggedEncodedCBOR
}

type DeviceRetrievalMethodType uint

const (
	DeviceRetrievalMethodTypeNFC       DeviceRetrievalMethodType = 1
	DeviceRetrievalMethodTypeBLE       DeviceRetrievalMethodType = 2
	DeviceRetrievalMethodTypeWiFiAware DeviceRetrievalMethodType = 3
)

type DeviceRetrievalMethod struct {
	Type             DeviceRetrievalMethodType
	Version          uint
	RetrievalOptions RetrievalOptions
}

type intermediateDeviceRetrievalMethod struct {
	_                struct{} `cbor:",toarray"`
	Type             DeviceRetrievalMethodType
	Version          uint
	RetrievalOptions cbor.RawMessage
}

func (drm *DeviceRetrievalMethod) MarshalCBOR() ([]byte, error) {
	var err error

	var retrievalOptionsBytes []byte
	switch retrievalOptions := drm.RetrievalOptions.(type) {
	case WifiOptions:
		retrievalOptionsBytes, err = cbor.Marshal(&retrievalOptions)
		if err != nil {
			return nil, err
		}

	case BLEOptions:
		retrievalOptionsBytes, err = cbor.Marshal(&retrievalOptions)
		if err != nil {
			return nil, err
		}

	case NFCOptions:
		retrievalOptionsBytes, err = cbor.Marshal(&retrievalOptions)
		if err != nil {
			return nil, err
		}

	default:
		return nil, ErrUnrecognisedRetrievalMethod
	}

	intermediateDeviceRetrievalMethod := intermediateDeviceRetrievalMethod{
		Type:             drm.Type,
		Version:          drm.Version,
		RetrievalOptions: retrievalOptionsBytes,
	}
	return cbor.Marshal(&intermediateDeviceRetrievalMethod)
}

func (drm *DeviceRetrievalMethod) UnmarshalCBOR(data []byte) error {
	var err error

	var intermediateDeviceRetrievalMethod intermediateDeviceRetrievalMethod
	if err = cbor.Unmarshal(data, &intermediateDeviceRetrievalMethod); err != nil {
		return err
	}

	var retrievalOptions RetrievalOptions
	switch intermediateDeviceRetrievalMethod.Type {
	case DeviceRetrievalMethodTypeWiFiAware:
		var wifiOptions WifiOptions
		if err = cbor.Unmarshal(intermediateDeviceRetrievalMethod.RetrievalOptions, &wifiOptions); err != nil {
			return err
		}
		retrievalOptions = wifiOptions

	case DeviceRetrievalMethodTypeBLE:
		var bleOptions BLEOptions
		if err = cbor.Unmarshal(intermediateDeviceRetrievalMethod.RetrievalOptions, &bleOptions); err != nil {
			return err
		}
		retrievalOptions = bleOptions

	case DeviceRetrievalMethodTypeNFC:
		var nfcOptions NFCOptions
		if err = cbor.Unmarshal(intermediateDeviceRetrievalMethod.RetrievalOptions, &nfcOptions); err != nil {
			return err
		}
		retrievalOptions = nfcOptions

	default:
		return ErrUnrecognisedRetrievalMethod
	}

	drm.Type = intermediateDeviceRetrievalMethod.Type
	drm.Version = intermediateDeviceRetrievalMethod.Version
	drm.RetrievalOptions = retrievalOptions

	return nil
}

type RetrievalOptions any

type WifiOptions struct {
	PassPhraseInfoPassPhrase  string `cbor:"0,keyasint,omitempty"`
	ChannelInfoOperatingClass uint   `cbor:"1,keyasint,omitempty"`
	ChannelInfoChannelNumber  uint   `cbor:"2,keyasint,omitempty"`
	BandInfoSupportedBands    []byte `cbor:"3,keyasint,omitempty"`
}

type BLEOptions struct {
	SupportsPeripheralServer      bool       `cbor:"0,keyasint"`
	SupportsCentralClient         bool       `cbor:"1,keyasint"`
	PeripheralServerUUID          *uuid.UUID `cbor:"10,keyasint,omitempty"`
	CentralClientUUID             *uuid.UUID `cbor:"11,keyasint,omitempty"`
	PeripheralServerDeviceAddress []byte     `cbor:"20,keyasint,omitempty"`
}

type NFCOptions struct {
	MaxLengthCommandData  uint `cbor:"0,keyasint"`
	MaxLengthResponseData uint `cbor:"1,keyasint"`
}
