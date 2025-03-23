package main

import (
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

/*
	Parse a PCRs string list to []uint
*/
func ParsePCRs(s string) ([]uint, error) {
	var pcrs []uint
	if len(s) > 0 {
		for _, s := range strings.Split(s, ",") {
			pcr, err := strconv.Atoi(s)
			if err != nil {
				return nil, err
			}
			pcrs = append(pcrs, uint(pcr))
		}
	}

	logrus.Debugf("Using the following PCRs: %s", s)
	return pcrs, nil
}