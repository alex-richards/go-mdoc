package issuer

import (
	"io"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/veraison/go-cose"
)

func NewIssuerAuth(
	rand io.Reader,
	issuerAuthority IssuerAuthority,
	mobileSecurityObject *mdoc.MobileSecurityObject,
) (*mdoc.IssuerAuth, error) {
	mobileSecurityObjectBytes, err := cbor.MarshalToNewTaggedEncodedCBOR(mobileSecurityObject)
	if err != nil {
		return nil, err
	}

	issuerAuth := &mdoc.IssuerAuth{
		Headers: cose.Headers{
			Unprotected: cose.UnprotectedHeader{
				cose.HeaderLabelX5Chain: issuerAuthority.DocumentSignerCertificate.Raw,
			},
		},
		Payload: mobileSecurityObjectBytes.TaggedValue,
	}

	sign1 := (*cose.Sign1Message)(issuerAuth)

	err = sign1.Sign(rand, []byte{}, mdoc.CoseSigner{issuerAuthority.Signer})
	if err != nil {
		return nil, err
	}

	return issuerAuth, nil
}

func NewMobileSecurityObject(
	docType mdoc.DocType,
	digestAlgorithm mdoc.DigestAlgorithm,
	nameSpaces mdoc.IssuerNameSpaces,
	sDeviceKey *mdoc.PublicKey,
	validityInfo *mdoc.ValidityInfo,
	keyAuthorizations *mdoc.KeyAuthorizations,
	keyInfo *mdoc.KeyInfo,
) (*mdoc.MobileSecurityObject, error) {
	hash, err := digestAlgorithm.Hash()
	if err != nil {
		return nil, err
	}

	nameSpaceDigests := make(mdoc.NameSpaceDigests, len(nameSpaces))
	for nameSpace, issuerSignedItemBytess := range nameSpaces {
		valueDigests := make(mdoc.ValueDigests, len(issuerSignedItemBytess))
		nameSpaceDigests[nameSpace] = valueDigests
		for _, issuerSignedItemBytes := range issuerSignedItemBytess {
			issuerSignedItem, err := issuerSignedItemBytes.IssuerSignedItem()
			if err != nil {
				return nil, err
			}

			hash.Reset()
			hash.Write(issuerSignedItemBytes.TaggedValue)
			h := hash.Sum(nil)
			_, exists := valueDigests[issuerSignedItem.DigestID]
			if exists {
				return nil, mdoc.ErrDuplicateDigestID
			}
			valueDigests[issuerSignedItem.DigestID] = h
		}
	}

	return &mdoc.MobileSecurityObject{
		Version:         mdoc.MobileSecurityObjectVersion,
		DigestAlgorithm: digestAlgorithm,
		ValueDigests:    nameSpaceDigests,
		DeviceKeyInfo: mdoc.DeviceKeyInfo{
			DeviceKey:         *sDeviceKey,
			KeyAuthorizations: keyAuthorizations,
			KeyInfo:           keyInfo,
		},
		DocType:      docType,
		ValidityInfo: *validityInfo,
	}, nil
}
