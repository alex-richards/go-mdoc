package spec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/alex-richards/go-mdoc"
	mdocecdsa "github.com/alex-richards/go-mdoc/cipher_suite/ecdsa"
	mdoccbor "github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/alex-richards/go-mdoc/internal/testutil"
	"github.com/alex-richards/go-mdoc/issuer"
	"github.com/veraison/go-cose"

	"github.com/fxamacker/cbor/v2"
)

func Test_IssueMDoc(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)

	now := time.UnixMilli(1500)

	sDeviceKey, err := mdocecdsa.GeneratePrivateKey(rand, mdoc.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	items := map[string]map[string]string{
		"nameSpace1": {
			"dataElementIdentifier1": "value1",
			"dataElementIdentifier2": "value2",
		},
		"nameSpace2": {
			"dataElementIdentifier1": "value1",
			"dataElementIdentifier2": "value2",
		},
	}

	nameSpaces := make(mdoc.IssuerNameSpaces, len(items))

	for nameSpace, dataElements := range items {
		digestID := mdoc.DigestID(0)

		issuerSignedItemBytess := make([]mdoc.IssuerSignedItemBytes, len(dataElements))
		nameSpaces[mdoc.NameSpace(nameSpace)] = issuerSignedItemBytess

		for dataElementIdentifier, dataElementValue := range dataElements {
			r := make([]byte, 16)
			n, err := rand.Read(r)
			if err != nil || n != 16 {
				t.Fatal(err)
			}

			issuerSignedItem := mdoc.IssuerSignedItem{
				DigestID:          digestID,
				Random:            r,
				ElementIdentifier: mdoc.DataElementIdentifier(dataElementIdentifier),
				ElementValue:      dataElementValue,
			}

			issuerSignedItemBytes, err := mdoccbor.MarshalToNewTaggedEncodedCBOR(issuerSignedItem)
			if err != nil {
				t.Fatal(err)
			}
			issuerSignedItemBytess[digestID] = (mdoc.IssuerSignedItemBytes)(*issuerSignedItemBytes)

			digestID++
		}
	}

	digestAlgorithm := mdoc.DigestAlgorithmSHA256
	digest, err := digestAlgorithm.Hash()
	if err != nil {
		t.Fatal(err)
	}

	mobileSecurityObject, err := issuer.NewMobileSecurityObject(
		"docType1",
		digestAlgorithm,
		nameSpaces,
		&sDeviceKey.PublicKey,
		&mdoc.ValidityInfo{
			Signed:     time.UnixMilli(1000),
			ValidFrom:  time.UnixMilli(1000),
			ValidUntil: time.UnixMilli(2000),
		},
		nil,
		nil,
	)

	iacaKey, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand,
	)
	if err != nil {
		t.Fatal(err)
	}

	iacaCertificateDer, err := issuer.NewIACACertificate(
		rand,
		iacaKey, iacaKey.Public(),
		*big.NewInt(1234),
		"Test IACA",
		"NZ", nil,
		time.UnixMilli(1000),
		time.UnixMilli(2000),
	)
	if err != nil {
		t.Fatal(err)
	}

	iacaCertificate, err := x509.ParseCertificate(iacaCertificateDer)
	if err != nil {
		t.Fatal(err)
	}

	documentSignerKey, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand,
	)
	if err != nil {
		t.Fatal(err)
	}

	documentSigner, err := mdocecdsa.NewPrivateKey(documentSignerKey)
	if err != nil {
		t.Fatal(err)
	}

	documentSignerCertificateDer, err := issuer.NewDocumentSignerCertificate(
		rand,
		iacaKey, iacaCertificate,
		documentSignerKey.Public(),
		*big.NewInt(5678),
		"Test Document Signer",
		nil,
		time.UnixMilli(1000),
		time.UnixMilli(2000),
	)
	if err != nil {
		t.Fatal(err)
	}

	documentSignerCertificate, err := x509.ParseCertificate(documentSignerCertificateDer)
	if err != nil {
		t.Fatal(err)
	}

	issuerAuthority := issuer.IssuerAuthority{
		Signer:                    documentSigner.Signer,
		DocumentSignerCertificate: documentSignerCertificate,
	}

	issuerAuth, err := issuer.NewIssuerAuth(rand, issuerAuthority, mobileSecurityObject)
	if err != nil {
		t.Fatal(err)
	}

	issuerSigned := mdoc.IssuerSigned{
		IssuerAuth: *issuerAuth,
		NameSpaces: nameSpaces,
	}

	issuerSignedEncoded, err := cbor.Marshal(issuerSigned)
	if err != nil {
		t.Fatal(err)
	}

	var decoded mdoc.IssuerSigned
	err = cbor.Unmarshal(issuerSignedEncoded, &decoded)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := cose.NewVerifier(
		cose.AlgorithmES256,
		documentSignerKey.Public(),
	)
	err = (*cose.Sign1Message)(&decoded.IssuerAuth).Verify([]byte{}, verifier)
	if err != nil {
		t.Fatal(err)
	}

	_, err = decoded.Verify([]*x509.Certificate{iacaCertificate}, now)
	if err != nil {
		t.Fatal(err)
	}

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
