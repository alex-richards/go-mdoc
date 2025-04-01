package mdoc

import (
	"bytes"
	"crypto/x509"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"io"
	"time"
)

var (
	ErrMissingDigest               = errors.New("mdoc: missing digest")
	ErrInvalidDigest               = errors.New("mdoc: incorrect digest")
	ErrUnauthorizedDeviceNameSpace = errors.New("mdoc: unauthorized device name space")
)

type DeviceResponse struct {
	Version        string          `cbor:"version"`
	Documents      []Document      `cbor:"documents,omitempty"`
	DocumentErrors []DocumentError `cbor:"documentErrors,omitempty"`
	Status         StatusCode      `cbor:"status"`
}

type StatusCode uint

const (
	StatusCodeOK                  StatusCode = 0
	StatusCodeGeneralError        StatusCode = 10
	StatusCodeCBORDecodingError   StatusCode = 11
	StatusCodeCBORValidationError StatusCode = 12
)

func CreateDeviceResponse(
	deviceRequest *DeviceRequest,
	candidateIssuerSigneds map[DocType]IssuerSigned,
	candidateDeviceSigneds map[DocType]map[NameSpace]map[DataElementIdentifier]any,
	rand io.Reader,
	privateSDeviceKey PrivateSDeviceKey,
	sessionTranscript *SessionTranscript,
) (*DeviceResponse, error) {
	documents := make([]Document, 0)
	documentErrors := make([]DocumentError, 0)

	for _, docRequest := range deviceRequest.DocRequests {
		itemsRequest, err := docRequest.ItemsRequest()
		if err != nil {
			return nil, err
		}

		candidateIssuerSigned, ok := candidateIssuerSigneds[itemsRequest.DocType]
		if !ok {
			documentErrors = append(documentErrors, DocumentError{
				itemsRequest.DocType: ErrorCodeDataNotReturned,
			})
			continue
		}

		requestNameSpaces := itemsRequest.NameSpaces
		documentIssuerNameSpaces, err := candidateIssuerSigned.NameSpaces.Filter(requestNameSpaces.Contains)
		if err != nil {
			return nil, err
		}

		documentIssuerSignedItems, err := documentIssuerNameSpaces.IssuerSignedItems()
		if err != nil {
			return nil, err
		}
		requestNameSpaces = itemsRequest.NameSpaces.Filter(documentIssuerSignedItems.Contains)

		documentDeviceNameSpaces := make(DeviceNameSpaces)
		if len(candidateDeviceSigneds) > 0 && len(requestNameSpaces) > 0 {
			mobileSecurityObject, err := candidateIssuerSigned.IssuerAuth.MobileSecurityObject()
			if err != nil {
				return nil, err
			}

			keyAuthorizations := mobileSecurityObject.DeviceKeyInfo.KeyAuthorizations
			if keyAuthorizations != nil {
				authorizedDeviceNameSpaces := requestNameSpaces.Filter(keyAuthorizations.Contains)
				candidateDeviceSignedItems := candidateDeviceSigneds[itemsRequest.DocType]
				for authorizedDeviceNameSpace, authorizedDeviceDataElements := range authorizedDeviceNameSpaces {
					candidateDeviceNameSpace := candidateDeviceSignedItems[authorizedDeviceNameSpace]
					for authorizedDeviceDataElementIdentifier := range authorizedDeviceDataElements {
						candidateDeviceSignedItem, ok := candidateDeviceNameSpace[authorizedDeviceDataElementIdentifier]
						if ok {
							documentDeviceSignedItems, ok := documentDeviceNameSpaces[authorizedDeviceNameSpace]
							if !ok {
								documentDeviceSignedItems = make(DeviceSignedItems)
								documentDeviceNameSpaces[authorizedDeviceNameSpace] = documentDeviceSignedItems
							}
							documentDeviceSignedItems[authorizedDeviceDataElementIdentifier] = candidateDeviceSignedItem
						}
					}
				}
			}
		}

		requestNameSpaces = requestNameSpaces.Filter(documentDeviceNameSpaces.Contains)
		var documentErrors *Errors
		if len(requestNameSpaces) > 0 {
			*documentErrors = make(Errors)
			for nameSpace, dataElements := range requestNameSpaces {
				(*documentErrors)[nameSpace] = make(ErrorItems)
				for dataElement, _ := range dataElements {
					(*documentErrors)[nameSpace][dataElement] = ErrorCodeDataNotReturned
				}
			}
		}

		documentDeviceSigned, err := NewDeviceSigned(itemsRequest.DocType, documentDeviceNameSpaces, rand, privateSDeviceKey, sessionTranscript)
		if err != nil {
			return nil, err
		}

		documents = append(
			documents,
			Document{
				DocType: itemsRequest.DocType,
				IssuerSigned: IssuerSigned{
					NameSpaces: documentIssuerNameSpaces,
					IssuerAuth: candidateIssuerSigned.IssuerAuth,
				},
				DeviceSigned: *documentDeviceSigned,
				Errors:       documentErrors,
			},
		)
	}

	return NewDeviceResponse(
		documents,
		documentErrors,
		StatusCodeOK,
	), nil
}

func NewDeviceResponse(
	documents []Document,
	documentErrors []DocumentError,
	status StatusCode,
) *DeviceResponse {
	return &DeviceResponse{
		"1.0",
		documents,
		documentErrors,
		status,
	}
}

type DocumentError map[DocType]ErrorCode

type Document struct {
	DocType      DocType      `cbor:"docType"`
	IssuerSigned IssuerSigned `cbor:"issuerSigned"`
	DeviceSigned DeviceSigned `cbor:"deviceSigned"`
	Errors       *Errors      `cbor:"errors,omitempty"`
}

func (d *Document) Verify(
	rootCertificates []*x509.Certificate,
	now time.Time,
	sessionTranscript *SessionTranscript,
) error {
	mobileSecurityObject, err := d.IssuerSigned.Verify(rootCertificates, now)
	if err != nil {
		return err
	}

	deviceAuthenticationBytes, err := NewDeviceAuthenticationBytes(sessionTranscript, d.DocType, &d.DeviceSigned.NameSpacesBytes)
	if err != nil {
		return err
	}

	return d.DeviceSigned.Verify(&mobileSecurityObject.DeviceKeyInfo.DeviceKey, deviceAuthenticationBytes, mobileSecurityObject)
}

type IssuerSigned struct {
	NameSpaces IssuerNameSpaces `cbor:"nameSpaces,omitempty"`
	IssuerAuth IssuerAuth       `cbor:"issuerAuth"`
}

func (is IssuerSigned) Verify(rootCertificates []*x509.Certificate, now time.Time) (*MobileSecurityObject, error) {
	err := is.IssuerAuth.Verify(rootCertificates, now)
	if err != nil {
		return nil, err
	}

	mobileSecurityObject, err := is.IssuerAuth.MobileSecurityObject()
	if err != nil {
		return nil, err
	}

	hash, err := mobileSecurityObject.DigestAlgorithm.Hash()
	if err != nil {
		return nil, err
	}

	for nameSpace, issuerSignedItemBytess := range is.NameSpaces {
		nameSpaceDigests, ok := mobileSecurityObject.ValueDigests[nameSpace]
		if !ok {
			return nil, ErrMissingDigest
		}

		for _, issuerSignedItemBytes := range issuerSignedItemBytess {
			issuerSignedItem, err := issuerSignedItemBytes.IssuerSignedItem()
			if err != nil {
				return nil, err
			}

			expectedDigest, ok := nameSpaceDigests[issuerSignedItem.DigestID]
			if !ok {
				return nil, ErrMissingDigest
			}

			hash.Reset()
			hash.Write(issuerSignedItemBytes.TaggedValue)
			calculatedDigest := hash.Sum(nil)

			if !bytes.Equal(calculatedDigest, expectedDigest) {
				return nil, ErrInvalidDigest
			}
		}
	}

	return mobileSecurityObject, nil
}

type IssuerNameSpaces map[NameSpace]IssuerSignedItemBytess

func (ins IssuerNameSpaces) Filter(filter func(nameSpace NameSpace, dataElementIdentifier DataElementIdentifier) bool) (IssuerNameSpaces, error) {
	filteredIssuerNameSpaces := make(IssuerNameSpaces)
	for nameSpace, issuerSignedItemBytess := range ins {
		for _, issuerSignedItemBytes := range issuerSignedItemBytess {
			issuerSignedItem, err := issuerSignedItemBytes.IssuerSignedItem()
			if err != nil {
				return nil, err
			}

			if filter(nameSpace, issuerSignedItem.ElementIdentifier) {
				filteredIssuerSignedItemBytess, ok := filteredIssuerNameSpaces[nameSpace]
				if !ok {
					filteredIssuerSignedItemBytess = make(IssuerSignedItemBytess, 0)
				}
				filteredIssuerNameSpaces[nameSpace] = append(filteredIssuerSignedItemBytess, issuerSignedItemBytes)
			}
		}
	}
	return filteredIssuerNameSpaces, nil
}

func (ins IssuerNameSpaces) IssuerSignedItems() (IssuerSignedItems, error) {
	issuerSignedItemss := make(IssuerSignedItems, len(ins))
	for nameSpace, issuerSignedItemBytess := range ins {
		issuerSignedItems := make([]IssuerSignedItem, len(issuerSignedItemBytess))
		for i, issuerSignedItemBytes := range issuerSignedItemBytess {
			issuerSignedItem, err := issuerSignedItemBytes.IssuerSignedItem()
			if err != nil {
				return nil, err
			}
			issuerSignedItems[i] = *issuerSignedItem
		}
		issuerSignedItemss[nameSpace] = issuerSignedItems
	}
	return issuerSignedItemss, nil
}

type IssuerSignedItemBytess []IssuerSignedItemBytes
type IssuerSignedItemBytes TaggedEncodedCBOR

func (isib *IssuerSignedItemBytes) MarshalCBOR() ([]byte, error) {
	return (*TaggedEncodedCBOR)(isib).MarshalCBOR()
}

func (isib *IssuerSignedItemBytes) UnmarshalCBOR(data []byte) error {
	return (*TaggedEncodedCBOR)(isib).UnmarshalCBOR(data)
}

func (isib *IssuerSignedItemBytes) IssuerSignedItem() (*IssuerSignedItem, error) {
	issuerSignedItem := new(IssuerSignedItem)
	err := cbor.Unmarshal(isib.UntaggedValue, &issuerSignedItem)
	return issuerSignedItem, err
}

type IssuerSignedItems map[NameSpace][]IssuerSignedItem

func (isi IssuerSignedItems) Contains(nameSpace NameSpace, dataElementIdentifier DataElementIdentifier) bool {
	issuerSignedItems, ok := isi[nameSpace]
	if ok {
		for _, issuerSignedItem := range issuerSignedItems {
			if issuerSignedItem.ElementIdentifier == dataElementIdentifier {
				return true
			}
		}
	}
	return false
}

type IssuerSignedItem struct {
	DigestID          DigestID              `cbor:"digestID"`
	Random            []byte                `cbor:"random"`
	ElementIdentifier DataElementIdentifier `cbor:"elementIdentifier"`
	ElementValue      DataElementValue      `cbor:"elementValue"`
}

type DeviceSigned struct {
	NameSpacesBytes TaggedEncodedCBOR `cbor:"nameSpaces"`
	DeviceAuth      DeviceAuth        `cbor:"deviceAuth"`
}

func NewDeviceSigned(
	docType DocType,
	nameSpaces DeviceNameSpaces,
	rand io.Reader,
	privateSDeviceKey PrivateSDeviceKey,
	sessionTranscript *SessionTranscript,
) (*DeviceSigned, error) {
	nameSpacesBytes, err := MarshalToNewTaggedEncodedCBOR(nameSpaces)
	if err != nil {
		return nil, err
	}

	deviceAuthenticationBytes, err := NewDeviceAuthenticationBytes(sessionTranscript, docType, nameSpacesBytes)
	if err != nil {
		return nil, err
	}

	deviceAuth, err := NewDeviceAuth(rand, privateSDeviceKey, deviceAuthenticationBytes)
	if err != nil {
		return nil, err
	}

	return &DeviceSigned{
		NameSpacesBytes: *nameSpacesBytes,
		DeviceAuth:      *deviceAuth,
	}, nil
}

func (ds *DeviceSigned) Verify(
	deviceKey *DeviceKey,
	deviceAuthenticationBytes *TaggedEncodedCBOR,
	mobileSecurityObject *MobileSecurityObject,
) error {
	err := ds.DeviceAuth.Verify(deviceKey, deviceAuthenticationBytes)
	if err != nil {
		return err
	}

	deviceNameSpaces, err := ds.NameSpaces()
	if err != nil {
		return err
	}

	return deviceNameSpaces.Verify(mobileSecurityObject)
}

func (ds *DeviceSigned) NameSpaces() (DeviceNameSpaces, error) {
	var deviceNameSpaces DeviceNameSpaces
	if err := cbor.Unmarshal(ds.NameSpacesBytes.UntaggedValue, &deviceNameSpaces); err != nil {
		return nil, err
	}

	return deviceNameSpaces, nil
}

type DeviceNameSpaces map[NameSpace]DeviceSignedItems

func (dns DeviceNameSpaces) Verify(
	mobileSecurityObject *MobileSecurityObject,
) error {
	deviceNameSpaceCount := len(dns)
	if deviceNameSpaceCount == 0 {
		return nil
	}

	keyAuthorizations := mobileSecurityObject.DeviceKeyInfo.KeyAuthorizations

	for nameSpace, deviceSignedItems := range dns {
		for dataElementIdentifier := range deviceSignedItems {
			if keyAuthorizations == nil || !keyAuthorizations.Contains(nameSpace, dataElementIdentifier) {
				return ErrUnauthorizedDeviceNameSpace
			}
		}
	}

	return nil
}

func (dns DeviceNameSpaces) Contains(nameSpace NameSpace, dataElementIdentifier DataElementIdentifier) bool {
	dataElements, ok := dns[nameSpace]
	if ok {
		_, ok = dataElements[dataElementIdentifier]
		return ok
	}
	return false
}

type DeviceSignedItems map[DataElementIdentifier]DataElementValue

type Errors map[NameSpace]ErrorItems
type ErrorItems map[DataElementIdentifier]ErrorCode

type ErrorCode int

const (
	ErrorCodeDataNotReturned ErrorCode = 0
)
