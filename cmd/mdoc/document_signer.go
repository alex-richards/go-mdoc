package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/issuer"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/jawher/mow.cli"
)

func cmdDocSigner(cmd *cli.Cmd) {
	cmd.Command("create", "Create a new Document Signer Private Key and Certificate", cmdDocSignerCreate)
}

func cmdDocSignerCreate(cmd *cli.Cmd) {
	cmd.Spec = "IACA_PRIVATE_KEY IACA_CERTIFICATE SERIAL COMMON_NAME [STATE] NOT_BEFORE NOT_AFTER [OPTIONS]"

	iacaPrivateKey := new(ReaderValue)
	cmd.VarArg("IACA_PRIVATE_KEY", iacaPrivateKey, "Path to a PEM encoded IACA Private Key.")

	iacaCertificate := new(ReaderValue)
	cmd.VarArg("IACA_CERTIFICATE", iacaCertificate, "Path to a PEM encoded IACA Certificate.")

	serial := new(BigIntValue)
	cmd.VarArg("SERIAL", serial, "Certificate Serial Number.")

	commonName := cmd.StringArg("COMMON_NAME", "", "Certificate Common Name.")
	state := cmd.StringArg("STATE", "", "Certificate State or Province. Optional.")

	notBefore := new(TimeValue)
	cmd.VarArg("NOT_BEFORE", notBefore, "Certificate Valid From as an RFC3339 date.")

	notAfter := new(TimeValue)
	cmd.VarArg("NOT_AFTER", notAfter, "Certificate Valid To as an RFC3339 date.")

	curve := (CurveValue)(mdoc.CurveP256)
	cmd.VarOpt("C curve", &curve, "Private Key curve. One of P256, P384, P521, Ed25519.")

	keyFile := &WriterValue{
		value:      "-",
		withStdout: true,
	}
	cmd.VarOpt("k key-file", keyFile, "Private Key output file, defaults to stdout.")

	certFile := &WriterValue{
		value:      "-",
		withStdout: true,
	}
	cmd.VarOpt("c cert-file", certFile, "Certificate Output file, defaults to stdout.")

	cmd.Action = func() {
		var s *string
		if len(*state) > 0 {
			s = state
		}

		iacaPrivateKeyReadCloser, err := iacaPrivateKey.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer iacaPrivateKeyReadCloser.Close()

		iacaCertificateReadCloser, err := iacaCertificate.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer iacaCertificateReadCloser.Close()

		keyFileWriteCloser, err := keyFile.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer keyFileWriteCloser.Close()

		certFileWriteCloser, err := certFile.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer certFileWriteCloser.Close()

		cmdDocSignerCreateAction(
			curve.Get(),
			iacaPrivateKeyReadCloser,
			iacaCertificateReadCloser,
			serial.Get(),
			*commonName,
			s,
			notBefore.Get(),
			notAfter.Get(),
			keyFileWriteCloser,
			certFileWriteCloser,
		)
	}
}

func cmdDocSignerCreateAction(
	curve mdoc.Curve,
	iacaPrivateKeyReader io.Reader,
	iacaCertificateReader io.Reader,
	serial big.Int,
	commonName string,
	state *string,
	notBefore time.Time,
	notAfter time.Time,
	keyWriter io.Writer,
	certWriter io.Writer,
) {
	iacaPrivateKeyPEM, err := io.ReadAll(iacaPrivateKeyReader)
	if err != nil {
		log.Fatal(err)
	}

	iacaPrivateKeyDER, _ := pem.Decode(iacaPrivateKeyPEM)
	if iacaPrivateKeyDER == nil {
		log.Fatal("failed to decode IACA private key")
	}

	iacaPrivateKey, err := x509.ParseECPrivateKey(iacaPrivateKeyDER.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	iacaCertificatePEM, err := io.ReadAll(iacaCertificateReader)
	if err != nil {
		log.Fatal(err)
	}

	iacaCertificateDER, _ := pem.Decode(iacaCertificatePEM)
	if iacaCertificateDER == nil {
		log.Fatal("failed to decode IACA certificate")
	}

	iacaCertificate, err := x509.ParseCertificate(iacaCertificateDER.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	err = mdoc.ValidateIACACertificate(iacaCertificate)
	if err != nil {
		log.Fatal(err)
	}

	var documentSignerPrivateKey crypto.Signer
	var documentSignerPublicKey crypto.PublicKey
	switch curve {
	case mdoc.CurveP256:
		documentSignerPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		documentSignerPublicKey = documentSignerPrivateKey.Public()
	case mdoc.CurveP384:
		documentSignerPrivateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		documentSignerPublicKey = documentSignerPrivateKey.Public()
	case mdoc.CurveP521:
		documentSignerPrivateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		documentSignerPublicKey = documentSignerPrivateKey.Public()
	case mdoc.CurveEd25519:
		documentSignerPublicKey, documentSignerPrivateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
	case mdoc.CurveEd448:
		documentSignerPublicKey, documentSignerPrivateKey, err = ed448.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}

	default:
		log.Fatal(mdoc.ErrUnsupportedCurve)
	}

	documentSignerPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(documentSignerPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	err = pem.Encode(keyWriter, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: documentSignerPrivateKeyDER,
	})
	if err != nil {
		log.Fatal(err)
	}

	documentSignerCertificateDER, err := issuer.NewDocumentSignerCertificate(
		rand.Reader,
		iacaPrivateKey,
		iacaCertificate,
		documentSignerPublicKey,
		serial,
		commonName,
		state,
		notBefore,
		notAfter,
	)
	if err != nil {
		log.Fatal(err)
	}

	documentSignerCertificate, err := x509.ParseCertificate(documentSignerCertificateDER)
	if err != nil {
		log.Fatal(err)
	}

	err = mdoc.ValidateDocumentSignerCertificate(documentSignerCertificate, iacaCertificate)
	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(certWriter, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: documentSignerCertificateDER,
	})

	if err != nil {
		log.Fatal(err)
	}
}
