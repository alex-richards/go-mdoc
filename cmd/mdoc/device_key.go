package main

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/alex-richards/go-mdoc"
	"github.com/fxamacker/cbor/v2"
	cli "github.com/jawher/mow.cli"
	"log"
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
	cmd.VarOpt(" ", &out, "")

	cmd.Action = func() {
		curve := curveValue.Get()

		deviceKey, err := mdoc.NewSDeviceKey(rand.Reader, curve, mdoc.SDeviceKeyModeSign)
		if err != nil {
			log.Fatal(err)
		}

		encoded, err := cbor.Marshal(deviceKey)
		if err != nil {
			log.Fatal(err)
		}

		println(hex.EncodeToString(encoded))
	}
}
