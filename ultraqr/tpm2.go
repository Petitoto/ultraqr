package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/sirupsen/logrus"
)

type TPM struct {
	device string             // path to the TPM device
	t transport.TPMCloser     // connection to the TPM
	handles []tpm2.TPMHandle  // handles to flush when closing the connection
}

/*
	Open a TPM device connection
*/
func OpenTPM(device string) (TPM) {
	logrus.Debugf("TPM device: %s", device)
	rwc, err := tpmutil.OpenTPM(device)
	if err != nil {
		logrus.Fatal(err)
	}
	tpm := TPM{device, transport.FromReadWriteCloser(rwc), []tpm2.TPMHandle{}}
	return tpm
}

/*
	Log errors, close the TPM connection and exit
*/
func Fatal(tpm *TPM, details string, err error) {
	logrus.Error(details)
	logrus.Error(err)
	tpm.Close()
	os.Exit(1)
}

/*
	Close a TPM device connection
*/
func (tpm *TPM) Close() () {
	for _, handle := range tpm.handles {
		_, err := tpm2.FlushContext{FlushHandle: handle}.Execute(tpm.t)
		if err != nil {
			logrus.Errorf("Failed to flush handle 0x%x", handle)
		} else {
			logrus.Debugf("Flushed handle 0x%x", handle)
		}
	}
	transport.TPMCloser.Close(tpm.t)
	logrus.Debugf("Closed TPM device %s", tpm.device)
}

/*
	Returns a handle to the TPM Storage Rook Key (SRK).
	Create primary each time, to avoid dealing with TPM NVRAM.
	Primary seeds ensure that the created SRK will always
	be the same for same SRK template on the same TPM.
*/
func (tpm *TPM) GetSRK() (tpm2.AuthHandle) {
	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm.t)
	if err != nil {
		Fatal(tpm, "Failed to create primary SRK", err)
	}

	logrus.Debugf("Loaded primary SRK at 0x%x", srk.ObjectHandle)
	tpm.handles = append(tpm.handles, srk.ObjectHandle)
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
func (tpm *TPM) CreateKey() {
	var priv, pub []byte
	srk := tpm.GetSRK()

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
	}.Execute(tpm.t)
	if err != nil {
		Fatal(tpm, "Failed to create a new key", err)
	}

	priv = key.OutPrivate.Buffer
	pub = key.OutPublic.Bytes()

	var fpriv, fpub *os.File
	if err := os.MkdirAll(KEYS_PATH, os.ModeDir); err != nil {
		Fatal(tpm, "Failed to create " + KEYS_PATH, err)
	}
	if fpriv, err = os.OpenFile(KEYS_PATH + "key.priv", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600); err != nil {
		Fatal(tpm, "Failed to open " + KEYS_PATH + "key.priv", err)
	}
	defer fpriv.Close()
	if fpub, err = os.OpenFile(KEYS_PATH + "key.pub", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600); err != nil {
		Fatal(tpm, "Failed to open " + KEYS_PATH + "key.pub", err)
	}
	defer fpub.Close()
	if _, err = fpriv.Write(priv); err != nil {
		Fatal(tpm, "Failed to write private key to storage", err)
	}
	if _, err = fpub.Write(pub); err != nil {
		Fatal(tpm, "Failed to write public key to storage", err)
	}
	logrus.Debugf("Stored key in %s", KEYS_PATH)
}

/*
	Load key to the TPM from the saved
	public and private key files.
	Return a handle to the loaded key.
*/
func (tpm *TPM) LoadKey() (tpm2.NamedHandle) {
	var priv, pub []byte
	var err error

	if priv, err = os.ReadFile(KEYS_PATH + "key.priv"); err != nil {
		Fatal(tpm, "Failed to read private key from storage", err)
	}
	if pub, err = os.ReadFile(KEYS_PATH + "key.pub"); err != nil {
		Fatal(tpm, "Failed to read public key from storage", err)
	}

	srk := tpm.GetSRK()
	key, err := tpm2.Load{
		ParentHandle: srk,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](pub),
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: priv,
		},
	}.Execute(tpm.t)
	if err != nil {
		Fatal(tpm, "Failed to load the key", err)
	}

	logrus.Debugf("Loaded key at 0x%x", key.ObjectHandle)
	tpm.handles = append(tpm.handles, key.ObjectHandle)	
	return tpm2.NamedHandle{
		Handle: key.ObjectHandle,
		Name:   key.Name,
	}
}

/*
	Export the loaded public key to base64 DER format
*/
func (tpm *TPM) GetPubKey(hkey tpm2.NamedHandle) (string) {
	pub, err := tpm2.ReadPublic{
		ObjectHandle: hkey.Handle,
	}.Execute(tpm.t)
	if err != nil {
		Fatal(tpm, "Failed to read public part of the key", err)
	}

	outPub, err := pub.OutPublic.Contents()
	if err != nil {
		Fatal(tpm, "Failed to get public key content", err)
	}
	ecDetail, err := outPub.Parameters.ECCDetail()
	if err != nil {
		Fatal(tpm, "Failed to get public key details", err)
	}
	crv, err := ecDetail.CurveID.Curve()
	if err != nil {
		Fatal(tpm, "Failed to get public key curve", err)
	}
	eccUnique, err := outPub.Unique.ECC()
	if err != nil {
		Fatal(tpm, "Failed to get public key parameters", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		Fatal(tpm, "Failed to convert public key to DER form", err)
	}

	cert := base64.StdEncoding.EncodeToString(pubKeyDER)
	logrus.Debugf("Exported public key: %s", cert)
	return cert
}

/*
	Sign binary data using the loaded signing key.
*/
func (tpm *TPM) SignData(data []byte, hkey tpm2.NamedHandle) ([]byte) {
	digest := sha256.Sum256(data)

	logrus.Debugf("Hashed data: %x", digest)
	sig, err := tpm2.Sign{
		KeyHandle: hkey,
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}.Execute(tpm.t)
	if err != nil {
		Fatal(tpm, "Failed to sign data", err)
	}

	ecsig, err := sig.Signature.Signature.ECDSA()
	if err != nil {
		Fatal(tpm, "Failed to parse signature", err)
	}
	r := new(big.Int).SetBytes(ecsig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecsig.SignatureS.Buffer)

	signature, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
	if err != nil {
		Fatal(tpm, "Failed to format signature", err)
	}

	logrus.Debugf("Signature: %s", base64.StdEncoding.EncodeToString(signature))
	return signature
}