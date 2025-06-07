package main

import (
	"crypto/rand"
	"log"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/cipher_suite"
	"github.com/jawher/mow.cli"
)

func cmdDeviceKey(cmd *cli.Cmd) {
	cmd.Command("create", "", cmdDeviceKeyCreate)
}

func cmdDeviceKeyCreate(cmd *cli.Cmd) {
	cmd.Spec = "[CURVE] [OPTIONS]"

	curveValue := (CurveValue)(mdoc.CurveP256)
	cmd.VarArg("CURVE", &curveValue, "")

	out := WriterValue{
		value:      "-",
		withStdout: true,
	}
	cmd.VarOpt("", &out, "")

	cmd.Action = func() {
		curve := curveValue.Get()

		deviceKey, err := cipher_suite.GeneratePrivateKey(rand.Reader, curve, true)
		if err != nil {
			log.Fatal(err)
		}

		_ = deviceKey
		panic("TODO") // TODO
	}
}
