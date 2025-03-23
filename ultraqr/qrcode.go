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
func generateQRCode(data string, out string) (string, error) {
	logrus.Debugf("QR code data: %s", data)
	qr, err := qrcode.New(data, qrcode.Low)
	if err != nil {
		return "", err
	}

	if (out != "") {
		png, err := qr.PNG(256)
		if err != nil {
			return "", err
		}

		fh, err := os.Create(out)
		if err != nil {
			return "", err
		}
		defer fh.Close()

		_, err = fh.Write(png)
		if err != nil {
			return "", err
		}

		logrus.Debugf("Saved QR code data to: %s", out)
	}

	return qr.ToSmallString(false), nil
}