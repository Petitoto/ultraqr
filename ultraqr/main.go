package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

const KEYS_PATH = "/etc/ultraqr/"
var (
	initialize = flag.Bool("init", false, "Initialize UltraQR with a new signing key")
	enroll     = flag.Bool("enroll", false, "Enroll a new verifier device")
	verify     = flag.Bool("verify", false, "Verify measured boot state")
	verbose    = flag.Bool("verbose", false, "Use verbose logging")
	device     = flag.String("device", "/dev/tpm0", "Path to the TPM device to use")
)

func main() {
	flag.Parse()
	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	
	tpm := OpenTPM(*device)
	defer tpm.Close()

	if *initialize {
		logrus.Info("Generating a new signing key")
		tpm.CreateKey()
		logrus.Info("New key generated and sealed to the TPM!")

	} else if *enroll {
		logrus.Info("Retrieving public key")
		cert := tpm.GetPubCert(tpm.LoadKey())

		logrus.Info("Generating enrollment QR code")
		data := fmt.Sprintf("%x", cert)
		qrcode := generateQRCode(data)
		fmt.Print(qrcode)

	} else if *verify {
		logrus.Info("Unsealing signing key")
		key := tpm.LoadKey()

		logrus.Info("Signing current timestamp")
		timestamp := time.Now().Unix()
		signature := tpm.SignData(big.NewInt(timestamp).Bytes(), key)
		data := fmt.Sprintf(`{"t":"%d","s":"%x"}`, timestamp,
							base64.StdEncoding.EncodeToString(signature))

		logrus.Info("Generating verification QR code")
		qrcode := generateQRCode(data)
		fmt.Print(qrcode)

	} else {
		flag.Usage()
		os.Exit(1)
	}
}