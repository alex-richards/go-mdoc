package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"regexp"
	"time"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/cipher_suite"
	mdoccbor "github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/alex-richards/go-mdoc/issuer"
	"github.com/fxamacker/cbor/v2"
	cli "github.com/jawher/mow.cli"
)

func cmdIssuerSigned(cmd *cli.Cmd) {
	cmd.Command("create", "", cmdIssuerSignedCreate)
}

func cmdIssuerSignedCreate(cmd *cli.Cmd) {
	cmd.Spec = "DOCUMENT_SIGNER_PRIVATE_KEY DOCUMENT_SIGNER_CERTIFICATE DEVICE_KEY DOCTYPE ITEM... [OUT]"

	documentSignerPrivateKey := ReaderValue{}
	cmd.VarArg("DOCUMENT_SIGNER_PRIVATE_KEY", &documentSignerPrivateKey, "Path to PEM encoded Document Signer Private Key.")

	documentSignerCertificate := ReaderValue{}
	cmd.VarArg("DOCUMENT_SIGNER_CERTIFICATE", &documentSignerCertificate, "Path to PEM encoded Document Signer Certificate.")

	deviceKey := ReaderValue{}
	cmd.VarArg("DEVICE_KEY", &deviceKey, "Path to PEM encoded Public Device Key.")

	docType := cmd.StringArg("DOCTYPE", "", "Issuer Signed DocType.")
	items := cmd.StringsArg("ITEM", nil, "Claim items in the format: namespace:dei:value[:(tstr|bstr|tdate|full-date|uint|bool)]")

	out := WriterValue{
		value:      "-",
		withStdout: true,
	}
	cmd.VarArg("OUT", &out, "Issuer Signed output file. Defaults to stdout.")

	cmd.Action = func() {
		documentSignerPrivateKeyReadCloser, err := documentSignerPrivateKey.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer documentSignerPrivateKeyReadCloser.Close()

		documentSignerCertificateReadCloser, err := documentSignerCertificate.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer documentSignerCertificateReadCloser.Close()

		deviceKeyReadCloser, err := deviceKey.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer deviceKeyReadCloser.Close()

		cmdIssuerSignedCreateAction(
			documentSignerPrivateKeyReadCloser,
			documentSignerCertificateReadCloser,
			deviceKeyReadCloser,
			*docType,
			*items,
		)
	}
}

func cmdIssuerSignedCreateAction(
	documentSignerPrivateKeyReader io.Reader,
	documentSignerCertificateReader io.Reader,
	deviceKeyReader io.Reader,
	docType string,
	items []string,
) {
	var issuerAuthority issuer.IssuerAuthority
	{
		privateKey, err := readPrivateKeyFromPEM(documentSignerPrivateKeyReader)
		if err != nil {
			log.Fatal(err)
		}

		certificate, err := readCertificateFromPEM(documentSignerCertificateReader)
		if err != nil {
			log.Fatal(err)
		}

		issuerAuthority = issuer.IssuerAuthority{
			Signer:                    cryptoSigner{privateKey},
			DocumentSignerCertificate: certificate,
		}
	}

	nameSpaces := make(map[mdoc.NameSpace]map[mdoc.DataElementIdentifier]mdoc.DataElementValue)
	{
		inputItemPattern, err := regexp.Compile("^([a-z0-9.]+):([a-z0-9]+):([a-z0-9]+)(@(tstr|bstr|tdate|full-date|uint|bool))?$")
		if err != nil {
			panic(err)
		}

		for _, item := range items {
			match := inputItemPattern.FindStringSubmatch(item)
			if match == nil {
				log.Fatalf("invalid item: %s", item)
			}

			inputNameSpace := match[1]
			inputDataElementIdentifier := match[2]
			inputValue := match[3]
			inputType := mdoccbor.CBORType(match[4])

			var parsedValue mdoc.DataElementValue
			switch inputType {
			case "":
			case mdoccbor.CBORTypeTstr:
				parsedValue = inputValue

			case mdoccbor.CBORTypeBstr:
				parsedValue, err = hex.DecodeString(inputValue)
				if err != nil {
					log.Fatal(err)
				}

			case mdoccbor.CBORTypeTdate:
				// TODO
				log.Fatal("TODO")

			case mdoccbor.CBORTypeFullDate:
				// TODO
				log.Fatal("TODO")

			case mdoccbor.CBORTypeUint:
				// TODO
				log.Fatal("TODO")

			case mdoccbor.CBORTypeBool:
				switch inputValue {
				case "true":
					parsedValue = true
				case "false":
					parsedValue = false
				default:
					log.Fatalf("invalid value: %s", inputValue)
				}

			default:
				log.Fatalf("invalid type: %s", inputType)
			}

			nameSpace, exists := nameSpaces[mdoc.NameSpace(inputNameSpace)]
			if !exists {
				nameSpace = make(map[mdoc.DataElementIdentifier]mdoc.DataElementValue)
				nameSpaces[mdoc.NameSpace(inputNameSpace)] = nameSpace
			}

			_, exists = nameSpace[mdoc.DataElementIdentifier(inputDataElementIdentifier)]
			if exists {
				log.Fatalf("duplicate item: %s:%s", inputNameSpace, inputDataElementIdentifier)
			}

			nameSpace[mdoc.DataElementIdentifier(inputDataElementIdentifier)] = parsedValue
		}
	}

	issuerSigned := mdoc.IssuerSigned{
		NameSpaces: make(mdoc.IssuerNameSpaces),
	}

	{
		var digestID mdoc.DigestID
		for nameSpace, elements := range nameSpaces {
			issuerSigned.NameSpaces[nameSpace] = make([]mdoc.IssuerSignedItemBytes, 0, len(elements))
			for elementIdentifier, elementValue := range elements {
				issuerSignedItemBytes, err := mdoc.NewIssuerSignedItemBytes(rand.Reader, digestID, elementIdentifier, elementValue)
				if err != nil {
					log.Fatal(err)
				}

				issuerSigned.NameSpaces[nameSpace] = append(issuerSigned.NameSpaces[nameSpace], *issuerSignedItemBytes)

				digestID++
			}
		}
	}

	var deviceKey *mdoc.PublicKey
	{
		deviceKeyPEM, err := io.ReadAll(deviceKeyReader)
		if err != nil {
			log.Fatal(err)
		}

		deviceKeyDER, _ := pem.Decode(deviceKeyPEM)
		if deviceKeyDER == nil || deviceKeyDER.Type != "PUBLIC KEY" {
			log.Fatal("failed to decode deviceKey")
		}

		deviceKeyPublic, err := x509.ParsePKIXPublicKey(deviceKeyDER.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		deviceKey, err = cipher_suite.NewPublicKey(deviceKeyPublic)
		if err != nil {
			log.Fatal(err)
		}
	}

	{
		if len(docType) == 0 {
			log.Fatal("missing docType")
		}

		now := time.Now()

		mobileSecurityObject, err := issuer.NewMobileSecurityObject(
			(mdoc.DocType)(docType),
			mdoc.DigestAlgorithmSHA256,
			issuerSigned.NameSpaces,
			deviceKey,
			&mdoc.ValidityInfo{
				Signed:     now,
				ValidFrom:  now,
				ValidUntil: now.Add(1 * time.Hour), // TODO duration
			},
			nil,
			nil,
		)
		if err != nil {
			log.Fatal(err)
		}

		issuerAuth, err := issuer.NewIssuerAuth(
			rand.Reader,
			issuerAuthority,
			mobileSecurityObject,
		)
		if err != nil {
			log.Fatal(err)
		}
		issuerSigned.IssuerAuth = *issuerAuth
	}

	{
		issuerSignedBytes, err := cbor.Marshal(issuerSigned)
		if err != nil {
			log.Fatal(err)
		}

		println(hex.EncodeToString(issuerSignedBytes))
	}
}
