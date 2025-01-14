package main

import (
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/sirupsen/logrus"
)

/*
	Open a TPM device connection
*/
func openTPM() (transport.TPMCloser) {
	rwc, err := tpmutil.OpenTPM()
	if err != nil {
		logrus.Fatal(err)
	}
	return transport.FromReadWriteCloser(rwc)
}

/*
	Close a TPM device connection
*/
func closeTPM(tpm transport.TPMCloser) () {
	transport.TPMCloser.Close(tpm)
}

/*
	Returns a handle to the TPM Storage Rook Key (SRK).
	Create primary each time, to avoid dealing with TPM NVRAM.
	Primary seeds ensure that the created SRK will always
	be the same for same SRK template on the same TPM.
*/
func getSRK(tpm transport.TPMCloser) (tpm2.TPMHandle) {
	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		logrus.Fatal(err)
	}
	return srk.ObjectHandle
}

/*
	Create a signing key (ECC), seal it to the TPM
	following a policy matching the selected PCRs,
	and store its public and (sealed) private parts
	into two files. Overwrite existing files.
*/
func createKey(tpm transport.TPMCloser) {
	var priv, pub []byte
	srk := getSRK(tpm)
	key, err := tpm2.Create{
		ParentHandle: srk,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
		}),
		CreationPCR: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(0,2,4,8,9),
				},
			},
		},
	}.Execute(tpm)
	if err != nil {
		logrus.Fatal(err)
	}
	
	priv = key.OutPrivate.Buffer
	pub = key.OutPublic.Bytes()
	
	var fpriv, fpub *os.File
	if err := os.MkdirAll(KEYS_PATH, os.ModeDir); err != nil {
		logrus.Fatal(err)
	}
	if fpriv, err = os.OpenFile(KEYS_PATH + "key.priv", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600); err != nil {
		logrus.Fatal(err)
	}
	defer fpriv.Close()
	if fpub, err = os.OpenFile(KEYS_PATH + "key.pub", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600); err != nil {
		logrus.Fatal(err)
	}
	defer fpub.Close()
	if _, err = fpriv.Write(priv); err != nil {
		logrus.Fatal(err)
	}
	if _, err = fpub.Write(pub); err != nil {
		logrus.Fatal(err)
	}
}

/*
	Load key to the TPM from the saved
	public and private key files.
	Return a handle to the loaded key.
*/
func loadKey(tpm transport.TPMCloser) (tpm2.TPMHandle) {
	var priv, pub []byte
	var err error
	if priv, err = os.ReadFile(KEYS_PATH + "key.priv"); err != nil {
		logrus.Fatal(err)
	}
	if pub, err = os.ReadFile(KEYS_PATH + "key.pub"); err != nil {
		logrus.Fatal(err)
	}
	
	srk := getSRK(tpm)
	key, err := tpm2.Load{
		ParentHandle: srk,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](pub),
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: priv,
		},
	}.Execute(tpm)
	if err != nil {
		logrus.Fatal(err)
	}
	
	return key.ObjectHandle
}

/*
	Get the PEM certificate associated to
	the loaded public key.
*/
func getPubCert(tpm transport.TPMCloser, hkey tpm2.TPMHandle) (string) {
	
}

/*
	Sign binary data using the loaded signing key.
*/
func signData(tpm transport.TPMCloser, data []byte, hkey tpm2.TPMHandle) ([]byte) {
	
}