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

var (
	initialize = flag.Bool("init", false, "Initialize UltraQR with a new signing key")
	enroll     = flag.Bool("enroll", false, "Enroll a new verifier device")
	verify     = flag.Bool("verify", false, "Verify measured boot state")
	verbose    = flag.Bool("verbose", false, "Use verbose logging")
	device     = flag.String("device", "/dev/tpm0", "Path to the TPM device to use")
	key_path   = flag.String("key", "/etc/ultraqr", "Path to store the signing key public and private TPM parts")
	challenge  = flag.String("challenge", "", "Custom challenge to sign during verification")
	pcrs_str   = flag.String("pcrs", "0,2,4,7,8,9", "Selected PCRs for the authorization policy")
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
	
	pcrs := ParsePCRs(*pcrs_str)

	if *initialize {
		logrus.Info("Generating a new signing key")
		tpm.CreateKey(*key_path, pcrs)
		logrus.Info("New key generated and sealed to the TPM!")

	} else if *enroll {
		logrus.Info("Retrieving public key")
		cert := tpm.GetPubKey(tpm.LoadKey(*key_path, pcrs))

		logrus.Info("Generating enrollment QR code")
		qrcode := generateQRCode(cert)
		fmt.Print(qrcode)

	} else if *verify {
		logrus.Info("Unsealing signing key")
		key := tpm.LoadKey(*key_path, pcrs)

		var data string
		if (*challenge == "") {
			logrus.Info("Signing current timestamp")

			timestamp := time.Now().Unix()
			signature := tpm.SignData(big.NewInt(timestamp).Bytes(), key)
			data = fmt.Sprintf(`{"c":"%d","s":"%s"}`, timestamp,
								base64.StdEncoding.EncodeToString(signature))

		} else {
			logrus.Info("Signing provided challenge")

			signature := tpm.SignData([]byte(*challenge), key)
			data = fmt.Sprintf(`{"t":"%s","s":"%s"}`, challenge,
								base64.StdEncoding.EncodeToString(signature))
		}

		logrus.Info("Generating verification QR code")
		qrcode := generateQRCode(data)
		fmt.Print(qrcode)

	} else {
		flag.Usage()
		os.Exit(1)
	}
}