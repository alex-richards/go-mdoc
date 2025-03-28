package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/veraison/go-cose"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func Test_IssueMDoc(t *testing.T) {
	random := NewDeterministicRand()

	sDeviceKey, err := NewSDeviceKey(random, CurveP256, SDeviceKeyModeSign)
	if err != nil {
		t.Fatal(err)
	}

	sDeviceKeyPublic, err := sDeviceKey.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}

	digestAlgorithm := DigestAlgorithmSHA256
	digest, err := digestAlgorithm.Hash()
	if err != nil {
		t.Fatal(err)
	}

	items := map[string]map[string]string{
		"nameSpace1": {
			"dataElementIdentifier1": "value1",
			"dataElementIdentifier2": "value2",
		},
	}

	nameSpaces := make(IssuerNameSpaces, len(items))
	nameSpaceDigests := make(NameSpaceDigests, len(items))

	for nameSpace, dataElements := range items {
		digestID := DigestID(0)

		issuerSignedItemBytess := make(IssuerSignedItemBytess, len(dataElements))
		nameSpaces[NameSpace(nameSpace)] = issuerSignedItemBytess

		valueDigests := make(ValueDigests, len(dataElements))
		nameSpaceDigests[NameSpace(nameSpace)] = valueDigests

		for dataElementIdentifier, dataElementValue := range dataElements {
			r := make([]byte, 16)
			n, err := random.Read(r)
			if err != nil || n != 16 {
				t.Fatal(err)
			}

			issuerSignedItem := IssuerSignedItem{
				DigestID:          digestID,
				Random:            r,
				ElementIdentifier: DataElementIdentifier(dataElementIdentifier),
				ElementValue:      dataElementValue,
			}

			issuerSignedItemBytes, err := MarshalToNewTaggedEncodedCBOR(issuerSignedItem)
			if err != nil {
				t.Fatal(err)
			}
			issuerSignedItemBytess[digestID] = (IssuerSignedItemBytes)(*issuerSignedItemBytes)

			digest.Reset()
			digest.Write(issuerSignedItemBytes.TaggedValue)
			valueDigests[digestID] = digest.Sum(nil)

			digestID++
		}
	}

	mobileSecurityObject := MobileSecurityObject{
		Version:         "1.0",
		DigestAlgorithm: digestAlgorithm,
		ValueDigests:    nameSpaceDigests,
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey: *sDeviceKeyPublic,
		},
		DocType: "docType1",
		ValidityInfo: ValidityInfo{
			Signed:     time.Now(),
			ValidFrom:  time.Now(),
			ValidUntil: time.Now(),
		},
	}
	mobileSecurityObjectBytes, err := MarshalToNewTaggedEncodedCBOR(mobileSecurityObject)
	if err != nil {
		t.Fatal(err)
	}

	signingKey, err := ecdsa.GenerateKey(
		elliptic.P256(),
		random,
	)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := cose.NewSigner(
		cose.AlgorithmES256,
		signingKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	issuerSigned := IssuerSigned{
		IssuerAuth: IssuerAuth{
			Headers: cose.Headers{
				Protected:   cose.ProtectedHeader{},
				Unprotected: cose.UnprotectedHeader{},
			},
			Payload: mobileSecurityObjectBytes.TaggedValue,
		},
		NameSpaces: nameSpaces,
	}

	err = (*cose.Sign1Message)(&issuerSigned.IssuerAuth).Sign(
		random,
		nil,
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}

	issuerSignedEncoded, err := cbor.Marshal(issuerSigned)
	if err != nil {
		t.Fatal(err)
	}

	var decoded IssuerSigned
	err = cbor.Unmarshal(issuerSignedEncoded, &decoded)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := cose.NewVerifier(
		cose.AlgorithmES256,
		signingKey.Public(),
	)
	err = (*cose.Sign1Message)(&decoded.IssuerAuth).Verify([]byte{}, verifier)
	if err != nil {
		t.Fatal(err)
	}

	//err = decoded.Verify()
	//if err != nil {
	//	t.Fatal(err)
	//}

	decodedMobileSecurityObject, err := decoded.IssuerAuth.MobileSecurityObject()
	if err != nil {
		t.Fatal(err)
	}

	for nameSpace, issuerSignedItemBytess := range decoded.NameSpaces {
		for _, issuerSignedItemBytes := range issuerSignedItemBytess {
			issuerSignedItem, err := issuerSignedItemBytes.IssuerSignedItem()
			if err != nil {
				t.Fatal(err)
			}

			expectedDigest := decodedMobileSecurityObject.ValueDigests[nameSpace][issuerSignedItem.DigestID]

			digest.Reset()
			digest.Write(issuerSignedItemBytes.TaggedValue)
			calculatedDigest := digest.Sum(nil)
			if !bytes.Equal(expectedDigest, calculatedDigest) {
				t.Fatal("Digest does not match")
			}
		}
	}
}
