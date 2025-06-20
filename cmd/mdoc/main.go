package main

import (
	"os"

	"github.com/jawher/mow.cli"
)

func main() {
	app := cli.App("mdoc", "Manage ISO 18013-5 mDocs.")

	app.Command("iaca", "", cmdIaca)
	app.Command("document-signer", "", cmdDocSigner)
	app.Command("device-key", "", cmdDeviceKey)
	app.Command("issuer-signed", "", cmdIssuerSigned)

	_ = app.Run(os.Args)
}
