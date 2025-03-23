package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
)

/*
	Generate a QR code containing the string
	given as parameter, and returns it as a
	text-art string.
*/
func generateQRCode(data string, out string) (string) {
	logrus.Debugf("QR code data: %s", data)
	qr, err := qrcode.New(data, qrcode.Low)
	if err != nil {
		logrus.Fatal(err)
	}

	if (out != "") {
		png, err := qr.PNG(256)
		if err != nil {
			logrus.Fatal(err)
		}

		fh, err := os.Create(out)
		if err != nil {
			logrus.Fatal(err)
		}
		defer fh.Close()

		_, err = fh.Write(png)
		if err != nil {
			logrus.Fatal(err)
		}

		logrus.Debugf("Saved QR code data to: %s", out)
	}

	return qr.ToSmallString(false)
}