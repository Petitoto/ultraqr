package main

import (
	"github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
)

/*
	Generate a QR code containing the string
	given as parameter, and returns it as a
	text-art string.
*/
func generateQRCode(data string) (string) {
	logrus.Debugf("QR code data: %s", data)
	qr, err := qrcode.New(data, qrcode.Low)
	if err != nil {
		logrus.Fatal(err)
	}
	return qr.ToSmallString(false)
}