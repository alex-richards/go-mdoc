package main

import (
	"crypto/ecdsa"
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
	"github.com/jawher/mow.cli"
)

func cmdIaca(cmd *cli.Cmd) {
	cmd.Command("create", "Create a new IACA Private Key and Certificate.", cmdIacaCreate)
}

func cmdIacaCreate(cmd *cli.Cmd) {
	cmd.Spec = "SERIAL COMMON_NAME COUNTRY [STATE] NOT_BEFORE NOT_AFTER [OPTIONS]"

	var serial BigIntValue
	cmd.VarArg("SERIAL", &serial, "Certificate Serial Number.")

	commonName := cmd.StringArg("COMMON_NAME", "", "Certificate Common Name.")
	country := cmd.StringArg("COUNTRY", "", "Certificate Country Code as an ISO 3166 Alpha 2 or 3 value.")
	state := cmd.StringArg("STATE", "", "Certificate State or Province. Optional.")

	var notBefore TimeValue
	cmd.VarArg("NOT_BEFORE", &notBefore, "Certificate Valid From as an RFC3339 date.")

	var notAfter TimeValue
	cmd.VarArg("NOT_AFTER", &notAfter, "Certificate Valid To as an RFC3339 date.")

	curve := (CurveValue)(mdoc.CurveP256)
	cmd.VarOpt("C curve", &curve, "Private Key curve. One of P256, P384, P521.")

	keyFile := &WriterValue{
		value:      "-",
		withStdout: true,
	}
	cmd.VarOpt("k key-file", keyFile, "Private Key output file, defaults to stdout.")

	certFile := &WriterValue{
		value:      "-",
		withStdout: true,
	}
	cmd.VarOpt("c cert-file", certFile, "Certificate output file, defaults to stdout.")

	cmd.Before = func() {
	}

	cmd.Action = func() {
		var s *string
		if len(*state) > 0 {
			s = state
		}

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

		cmdIacaCreateAction(
			curve.Get(),
			serial.Get(),
			*commonName,
			*country,
			s,
			notBefore.Get(),
			notAfter.Get(),
			keyFileWriteCloser,
			certFileWriteCloser,
		)
	}
}

func cmdIacaCreateAction(
	curve mdoc.Curve,
	serial big.Int,
	commonName string,
	country string,
	state *string,
	notBefore time.Time,
	notAfter time.Time,
	privateKeyWriter io.Writer,
	certificateWriter io.Writer,
) {
	var ellipticCurve elliptic.Curve
	switch curve {
	case mdoc.CurveP256:
		ellipticCurve = elliptic.P256()
	case mdoc.CurveP384:
		ellipticCurve = elliptic.P384()
	case mdoc.CurveP521:
		ellipticCurve = elliptic.P521()
	default:
		log.Fatal(mdoc.ErrUnsupportedCurve)
	}

	privateKey, err := ecdsa.GenerateKey(ellipticCurve, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	err = pem.Encode(privateKeyWriter, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	if err != nil {
		log.Fatal(err)
	}

	iacaCertificateDER, err := issuer.NewIACACertificate(
		rand.Reader,
		privateKey,
		privateKey.Public(),
		serial,
		commonName,
		country,
		state,
		notBefore,
		notAfter,
	)
	if err != nil {
		log.Fatal(err)
	}

	iacaCertificate, err := x509.ParseCertificate(iacaCertificateDER)
	if err != nil {
		log.Fatal(err)
	}

	err = mdoc.ValidateIACACertificate(iacaCertificate)
	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(certificateWriter, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: iacaCertificateDER,
	})
	if err != nil {
		log.Fatal(err)
	}
}
