package main

import (
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
func createKey(tpm transport.TPMCloser, pcr string) {
	
}

/*
	Load key to the TPM from the saved
	public and private key files.
	Return a handle to the loaded key.
*/
func loadKey(tpm transport.TPMCloser) (int) {
	
}

/*
	Get the PEM certificate associated to
	the loaded public key.
*/
func getPubCert(tpm transport.TPMCloser, hkey int) (string) {
	
}

/*
	Sign binary data using the loaded signing key.
*/
func signData(tpm transport.TPMCloser, data []byte, hkey int) ([]byte) {
	
}