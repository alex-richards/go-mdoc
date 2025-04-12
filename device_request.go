package mdoc

import (
	"crypto/x509"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"io"
	"time"
)

var (
	ErrDeviceRequestUnsupportedVersion = errors.New("mdoc: unsupported device request version")
	ErrMissingReaderAuth               = errors.New("mdoc: missing reader auth")
)

const (
	DeviceRequestVersion = "1.0"
)

type DeviceRequest struct {
	Version     string       `cbor:"version"`
	DocRequests []DocRequest `cbor:"docRequests"`
}

func NewDeviceRequest(docRequests []DocRequest) *DeviceRequest {
	return &DeviceRequest{
		DeviceRequestVersion,
		docRequests,
	}
}

func (dr *DeviceRequest) Verify(
	rootCertificates []*x509.Certificate,
	now time.Time,
	sessionTranscript *SessionTranscript,
) error {
	if dr.Version != DeviceRequestVersion {
		return ErrDeviceRequestUnsupportedVersion
	}

	var err error
	for _, docRequest := range dr.DocRequests {
		err = docRequest.Verify(rootCertificates, now, sessionTranscript)
		if err != nil {
			return err
		}
	}

	return nil
}

type DocRequest struct {
	ItemsRequestBytes TaggedEncodedCBOR `cbor:"itemsRequest"`
	ReaderAuth        *ReaderAuth       `cbor:"readerAuth,omitempty"`
}

func NewDocRequest(itemsRequest *ItemsRequest) (*DocRequest, error) {
	itemsRequestBytes, err := MarshalToNewTaggedEncodedCBOR(itemsRequest)
	if err != nil {
		return nil, err
	}

	return &DocRequest{
		ItemsRequestBytes: *itemsRequestBytes,
		ReaderAuth:        nil,
	}, nil
}

func NewAuthenticatedDocRequest(
	rand io.Reader,
	readerAuthority ReaderAuthority,
	itemsRequest *ItemsRequest,
	sessionTranscript *SessionTranscript,
) (*DocRequest, error) {
	docRequest, err := NewDocRequest(itemsRequest)
	if err != nil {
		return nil, err
	}

	readerAuthenticationBytes, err := NewReaderAuthenticationBytes(sessionTranscript, &docRequest.ItemsRequestBytes)
	if err != nil {
		return nil, err
	}

	docRequest.ReaderAuth, err = NewReaderAuth(rand, readerAuthority, readerAuthenticationBytes)
	if err != nil {
		return nil, err
	}

	return docRequest, nil
}

func (dr DocRequest) ItemsRequest() (*ItemsRequest, error) {
	var itemsRequest ItemsRequest

	err := cbor.Unmarshal(dr.ItemsRequestBytes.UntaggedValue, &itemsRequest)
	if err != nil {
		return nil, err
	}

	return &itemsRequest, nil
}

func (dr DocRequest) Verify(
	rootCertificates []*x509.Certificate,
	now time.Time,
	sessionTranscript *SessionTranscript,
) error {
	if dr.ReaderAuth == nil {
		return ErrMissingReaderAuth
	}

	readerAuthenticationBytes, err := NewReaderAuthenticationBytes(
		sessionTranscript,
		&dr.ItemsRequestBytes,
	)
	if err != nil {
		return err
	}

	return dr.ReaderAuth.Verify(
		rootCertificates,
		now,
		readerAuthenticationBytes,
	)
}

type ItemsRequest struct {
	DocType     DocType        `cbor:"docType"`
	NameSpaces  NameSpaces     `cbor:"nameSpaces"`
	RequestInfo map[string]any `cbor:"requestInfo"`
}

type NameSpaces map[NameSpace]DataElements

func (ns NameSpaces) Contains(nameSpace NameSpace, dataElementIdentifier DataElementIdentifier) bool {
	dataElements, ok := ns[nameSpace]
	if ok {
		_, ok = dataElements[dataElementIdentifier]
		return ok
	}

	return false
}

func (ns NameSpaces) Filter(filter func(nameSpace NameSpace, dataElementIdentifier DataElementIdentifier) bool) NameSpaces {
	filteredNameSpaces := make(NameSpaces)
	for nameSpace, dataElements := range ns {
		for dataElementIdentifier, intentToRetain := range dataElements {
			if filter(nameSpace, dataElementIdentifier) {
				filteredDataElements, ok := filteredNameSpaces[nameSpace]
				if !ok {
					filteredDataElements = make(DataElements)
					filteredNameSpaces[nameSpace] = filteredDataElements
				}
				filteredDataElements[dataElementIdentifier] = intentToRetain
			}
		}
	}
	return filteredNameSpaces
}

type DataElements map[DataElementIdentifier]IntentToRetain
type IntentToRetain bool

type DocType string
type NameSpace string
type DataElementIdentifier string
type DataElementValue any

type TypedDataElementValue struct {
	CBORType CBORType
	Value    DataElementValue
}

func (v *TypedDataElementValue) MarshalCBOR() ([]byte, error) {
	return marshalCBORTypedValue(v.CBORType, v.Value)
}
