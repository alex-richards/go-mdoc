package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"regexp"
	"time"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/issuer"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/fxamacker/cbor/v2"
	cli "github.com/jawher/mow.cli"
	"github.com/veraison/go-cose"
)

func cmdIssuerSigned(cmd *cli.Cmd) {
	cmd.Command("create", "", cmdIssuerSignedCreate)
}

func cmdIssuerSignedCreate(cmd *cli.Cmd) {
	cmd.Spec = "DOCUMENT_SIGNER_PRIVATE_KEY DOCUMENT_SIGNER_CERTIFICATE DEVICE_KEY DOCTYPE ITEM... [OUT]"

	documentSignerPrivateKey := ReaderValue{}
	cmd.VarArg("DOCUMENT_SIGNER_PRIVATE_KEY", &documentSignerPrivateKey, "")

	documentSignerCertificate := ReaderValue{}
	cmd.VarArg("DOCUMENT_SIGNER_CERTIFICATE", &documentSignerCertificate, "")

	deviceKey := ReaderValue{}
	cmd.VarArg("DEVICE_KEY", &deviceKey, "")

	docType := cmd.StringArg("DOCTYPE", "", "")
	items := cmd.StringsArg("ITEM", nil, "")

	out := WriterValue{
		value:      "-",
		withStdout: true,
	}
	cmd.VarArg("OUT", &out, "")

	cmd.Action = func() {
		var issuerAuthority issuer.IssuerAuthority
		{
			reader, err := documentSignerPrivateKey.Open()
			if err != nil {
				log.Fatal(err)
			}
			defer reader.Close()

			privateKey, err := readPrivateKeyFromPEM(reader)
			if err != nil {
				log.Fatal(err)
			}

			reader, err = documentSignerCertificate.Open()
			if err != nil {
				log.Fatal(err)
			}
			defer reader.Close()

			certificate, err := readCertificateFromPEM(reader)
			if err != nil {
				log.Fatal(err)
			}

			issuerAuthority = issuer.IssuerAuthority{
				Signer:                    cryptoSigner{privateKey},
				DocumentSignerCertificate: certificate,
			}
		}

		var sdf mdoc.PublicKey
		{
			reader, err := deviceKey.Open()
			if err != nil {
				log.Fatal(err)
			}
			defer reader.Close()

			deviceKeyData, err := io.ReadAll(reader)
			if err != nil {
				log.Fatal(err)
			}

			err = cbor.Unmarshal(deviceKeyData, &sdf)
		}

		inputItemPattern, err := regexp.Compile("^([a-z0-9.]+):([a-z0-9]+):([a-z0-9]+)(@(tstr|bstr|tdate|full-date|uint|bool))?$")
		if err != nil {
			panic(err)
		}

		nameSpaces := make(map[mdoc.NameSpace]map[mdoc.DataElementIdentifier]mdoc.DataElementValue)

		for _, item := range *items {
			match := inputItemPattern.FindStringSubmatch(item)
			if match == nil {
				log.Fatalf("invalid item: %s", item)
			}

			inputNameSpace := match[1]
			inputDataElementIdentifier := match[2]
			inputValue := match[3]
			inputType := match[4]

			if len(inputType) > 0 {
				// TODO convert values
			}
			parsedValue := inputValue

			nameSpace, exists := nameSpaces[mdoc.NameSpace(inputNameSpace)]
			if !exists {
				nameSpace = make(map[mdoc.DataElementIdentifier]mdoc.DataElementValue)
				nameSpaces[mdoc.NameSpace(inputNameSpace)] = nameSpace
			}

			_, exists = nameSpace[mdoc.DataElementIdentifier(inputDataElementIdentifier)]
			if exists {
				// TODO duplicate
			}

			nameSpace[mdoc.DataElementIdentifier(inputDataElementIdentifier)] = parsedValue
		}

		fmt.Printf("namespaces = %#v\n", nameSpaces)

		issuerSigned := mdoc.IssuerSigned{
			NameSpaces: make(mdoc.IssuerNameSpaces),
		}

		var digestID mdoc.DigestID
		for nameSpace, elements := range nameSpaces {
			issuerSigned.NameSpaces[nameSpace] = make([]mdoc.IssuerSignedItemBytes, 0, len(elements))
			for elementIdentifier, elementValue := range elements {
				issuerSignedItemBytes, err := mdoc.CreateIssuerSignedItemBytes(rand.Reader, digestID, elementIdentifier, elementValue)
				if err != nil {
					log.Fatal(err)
				}

				issuerSigned.NameSpaces[nameSpace] = append(issuerSigned.NameSpaces[nameSpace], *issuerSignedItemBytes)

				digestID++
			}
		}

		now := time.Now()
		deviceKey := &mdoc.PublicKey{
			Type:      cose.KeyTypeEC2,
			Algorithm: 0,
			Params: map[any]any{
				cose.KeyLabelEC2Curve: cose.CurveP256,
				cose.KeyLabelEC2X:     []byte{1, 2, 3, 4},
				cose.KeyLabelEC2Y:     []byte{5, 6, 7, 8},
			},
		}

		mobileSecurityObject, err := issuer.NewMobileSecurityObject(
			(mdoc.DocType)(*docType),
			mdoc.DigestAlgorithmSHA256,
			issuerSigned.NameSpaces,
			deviceKey,
			&mdoc.ValidityInfo{
				Signed:     now,
				ValidFrom:  now,
				ValidUntil: now.Add(1 * time.Hour),
			},
			nil,
			nil,
		)

		issuerAuth, err := issuer.NewIssuerAuth(
			rand.Reader,
			issuerAuthority,
			mobileSecurityObject,
		)
		if err != nil {
			log.Fatal(err)
		}
		issuerSigned.IssuerAuth = *issuerAuth

		issuerSignedBytes, err := cbor.Marshal(issuerSigned)
		if err != nil {
			log.Fatal(err)
		}

		println(hex.EncodeToString(issuerSignedBytes))
	}
}

type cryptoSigner struct {
	signer crypto.Signer
}

func (s cryptoSigner) Curve() mdoc.Curve {
	switch privateKey := s.signer.(type) {
	case *ecdsa.PrivateKey:
		switch privateKey.Curve {
		case elliptic.P256():
			return mdoc.CurveP256
		case elliptic.P384():
			return mdoc.CurveP384
		case elliptic.P521():
			return mdoc.CurveP521
		}
	case ed25519.PrivateKey:
		return mdoc.CurveEd25519
	case ed448.PrivateKey:
		return mdoc.CurveEd448
	}

	return ""
}

func (s cryptoSigner) Sign(rand io.Reader, message []byte) ([]byte, error) {
	return s.signer.Sign(rand, message, nil)
}
