package main

import (
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

/*
	Parse a PCRs string list to []uint
*/
func ParsePCRs(s string) []uint {
	var pcrs []uint
	if len(s) > 0 {
		for _, s := range strings.Split(s, ",") {
			pcr, err := strconv.Atoi(s)
			if err != nil {
				logrus.Fatal(err)
			}
			pcrs = append(pcrs, uint(pcr))
		}
	}
	return pcrs
}