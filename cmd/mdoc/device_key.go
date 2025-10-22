package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"strings"

	"github.com/alex-richards/go-mdoc"
	"github.com/jawher/mow.cli"
)

func cmdDeviceKey(cmd *cli.Cmd) {
	cmd.Command("create", "Create a new Device Key.", cmdDeviceKeyCreate)
}

func cmdDeviceKeyCreate(cmd *cli.Cmd) {
	cmd.Spec = "[OPTIONS]"

	curve := CurveValue{
		value:     mdoc.CurveP256,
		supported: []mdoc.Curve{mdoc.CurveP256, mdoc.CurveP384, mdoc.CurveP521, mdoc.CurveEd25519, mdoc.CurveEd448, mdoc.CurveX25519, mdoc.CurveX448},
	}

	{
		desc := strings.Builder{}
		desc.WriteString("Device Key curve. One of ")
		desc.WriteString(curve.supported[0].Name())
		for _, sc := range curve.supported[1:] {
			desc.WriteString(", ")
			desc.WriteString(sc.Name())
		}
		desc.WriteString(".")
		cmd.VarOpt("C curve", &curve, desc.String())
	}

	privateKeyFile := WriterValue{
		value:      "-",
		withStdout: true,
	}
	cmd.VarOpt("k key-file private-key-file", &privateKeyFile, "Private Key output file, defaults to stdout.")

	publicKeyFile := WriterValue{
		value:      "-",
		withStdout: true,
	}
	cmd.VarOpt("p public-key-file", &publicKeyFile, "Public Key output file, defaults to stdout.")

	cmd.Action = func() {
		privateKeyFileWriteCloser, err := privateKeyFile.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer privateKeyFileWriteCloser.Close()

		publicKeyFileReadCloser, err := publicKeyFile.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer publicKeyFileReadCloser.Close()

		cmdDeviceKeyCreateAction(curve.Get(), privateKeyFileWriteCloser, publicKeyFileReadCloser)
	}
}

func cmdDeviceKeyCreateAction(
	curve mdoc.Curve,
	privateKeyWriter io.Writer,
	publicKeyWriter io.Writer,
) {
	var deviceKeyPrivate crypto.PrivateKey
	var deviceKeyPublic crypto.PublicKey
	switch curve {
	case mdoc.CurveP256:
		pk, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		deviceKeyPrivate = pk
		deviceKeyPublic = pk.Public()
	case mdoc.CurveP384:
		pk, err := ecdh.P384().GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		deviceKeyPrivate = pk
		deviceKeyPublic = pk.Public()
	case mdoc.CurveP521:
		pk, err := ecdh.P521().GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		deviceKeyPrivate = pk
		deviceKeyPublic = pk.Public()
	case mdoc.CurveX25519:
		pk, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		deviceKeyPrivate = pk
		deviceKeyPublic = pk.Public()
	case mdoc.CurveEd25519:
		var err error
		deviceKeyPublic, deviceKeyPrivate, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
	case mdoc.CurveX448, mdoc.CurveEd448:
		log.Fatal("TODO")
	default:
		panic("unreachable")
	}

	{
		deviceKeyPrivateDER, err := x509.MarshalPKCS8PrivateKey(deviceKeyPrivate)
		if err != nil {
			log.Fatal(err)
		}

		err = pem.Encode(privateKeyWriter, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: deviceKeyPrivateDER,
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	{
		deviceKeyPublicDER, err := x509.MarshalPKIXPublicKey(deviceKeyPublic)
		if err != nil {
			log.Fatal(err)
		}

		err = pem.Encode(publicKeyWriter, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: deviceKeyPublicDER,
		})
		if err != nil {
			log.Fatal(err)
		}
	}
}
