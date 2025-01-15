package main

import (
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/sirupsen/logrus"
)

/*
	Open a TPM device connection
*/
func openTPM(device string) (transport.TPMCloser) {
	logrus.Debugf("Opening %s...", device)
	rwc, err := tpmutil.OpenTPM(device)
	if err != nil {
		logrus.Fatal(err)
	}
	return transport.FromReadWriteCloser(rwc)
}

/*
	Close a TPM device connection
*/
func closeTPM(tpm transport.TPMCloser) () {
	logrus.Debug("Closing the TPM...")
	transport.TPMCloser.Close(tpm)
}

/*
	Returns a handle to the TPM Storage Rook Key (SRK).
	Create primary each time, to avoid dealing with TPM NVRAM.
	Primary seeds ensure that the created SRK will always
	be the same for same SRK template on the same TPM.
*/
func getSRK(tpm transport.TPMCloser) (tpm2.AuthHandle) {
	logrus.Debug("Creating primary SRK...")
	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		fatal(tpm, err)
	}

	return tpm2.AuthHandle{
		Handle: srk.ObjectHandle,
		Name:   srk.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}
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

	logrus.Debug("Creating a new key...")
	key, err := tpm2.Create{
		ParentHandle: srk,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
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
		fatal(tpm, err)
	}

	logrus.Debug("Storing public and private part of the (sealed) key...")
	priv = key.OutPrivate.Buffer
	pub = key.OutPublic.Bytes()

	var fpriv, fpub *os.File
	if err := os.MkdirAll(KEYS_PATH, os.ModeDir); err != nil {
		fatal(tpm, err)
	}
	if fpriv, err = os.OpenFile(KEYS_PATH + "key.priv", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600); err != nil {
		fatal(tpm, err)
	}
	defer fpriv.Close()
	if fpub, err = os.OpenFile(KEYS_PATH + "key.pub", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600); err != nil {
		fatal(tpm, err)
	}
	defer fpub.Close()
	if _, err = fpriv.Write(priv); err != nil {
		fatal(tpm, err)
	}
	if _, err = fpub.Write(pub); err != nil {
		fatal(tpm, err)
	}
}

/*
	Load key to the TPM from the saved
	public and private key files.
	Return a handle to the loaded key.
*/
func loadKey(tpm transport.TPMCloser) (tpm2.NamedHandle) {
	var priv, pub []byte
	var err error

	logrus.Debug("Retrieving key from storage...")
	if priv, err = os.ReadFile(KEYS_PATH + "key.priv"); err != nil {
		fatal(tpm, err)
	}
	if pub, err = os.ReadFile(KEYS_PATH + "key.pub"); err != nil {
		fatal(tpm, err)
	}

	logrus.Debug("Loading the key into TPM memory...")
	srk := getSRK(tpm)
	key, err := tpm2.Load{
		ParentHandle: srk,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](pub),
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: priv,
		},
	}.Execute(tpm)
	if err != nil {
		fatal(tpm, err)
	}
	

	return tpm2.NamedHandle{
		Handle: key.ObjectHandle,
		Name:   key.Name,
	}
}

/*
	Get the PEM certificate associated to
	the loaded public key.
*/
func getPubCert(tpm transport.TPMCloser, hkey tpm2.NamedHandle) (string) {
	logrus.Debug("Reading public part of the key...")
	cert, err := tpm2.ReadPublic{
		ObjectHandle: hkey.Handle,
	}.Execute(tpm)
	if err != nil {
		fatal(tpm, err)
	}

	return base64.StdEncoding.EncodeToString(cert.OutPublic.Bytes())
}

/*
	Sign binary data using the loaded signing key.
*/
func signData(tpm transport.TPMCloser, data []byte, hkey tpm2.NamedHandle) ([]byte) {
	logrus.Debug("Signing data...")
	sig, err := tpm2.Sign{
		KeyHandle: hkey,
		Digest: tpm2.TPM2BDigest{
			Buffer: data,
		},
	}.Execute(tpm)
	if err != nil {
		fatal(tpm, err)
	}

	logrus.Debug("Parsing signed data...")
	ecsig, err := sig.Signature.Signature.ECDSA()
	if err != nil {
		fatal(tpm, err)
	}
	r := new(big.Int).SetBytes(ecsig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecsig.SignatureS.Buffer)

	signature, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
	if err != nil {
		fatal(tpm, err)
	}
	return signature
}

/*
	Log errors, close the TPM connection and exit
*/
func fatal(tpm transport.TPMCloser, err error) {
	closeTPM(tpm)
	logrus.Fatal(err)
}