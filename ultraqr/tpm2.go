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
	Returns a handle to the TPM SRK in the "Owner" hierarchy
	(ECC SRK default template)
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
	Get a PCR policy digest for the selected PCRs
*/
func (tpm *TPM) GetPCRPolicy() (tpm2.TPM2BDigest) {
	sess, _, err := tpm2.PolicySession(tpm.t, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		Fatal(tpm, "Failed to create a policy session", err)
	}
	tpm.handles = append(tpm.handles, sess.Handle())

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(0,2,4,7,8,9),
				},
			},
		},
	}.Execute(tpm.t)
	if err != nil {
		Fatal(tpm, "Failed to create a PCR policy", err)
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(tpm.t)
	if err != nil {
		Fatal(tpm, "Failed to get PCR policy digest", err)
	}

	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(tpm.t)
	if err != nil {
		Fatal(tpm, "Failed to flush PCR policy context", err)
	}

	policy := pgd.PolicyDigest

	logrus.Debugf("PCR policy digest: %x", policy.Buffer)
	return policy
}

/*
	Get a PCR policy authorization session for the selected PCRs
*/
func (tpm *TPM) GetPCRAuth() (tpm2.Session) {
	sess, _, err := tpm2.PolicySession(tpm.t, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{}...)
	if err != nil {
		Fatal(tpm, "Failed to create a policy session", err)
	}
	tpm.handles = append(tpm.handles, sess.Handle())

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(0,2,4,7,8,9),
				},
			},
		},
	}.Execute(tpm.t)
	if err != nil {
		Fatal(tpm, "Failed to create a PCR policy", err)
	}
	
	return sess
}

/*
	Create a signing key (ECC), bind it to a PCR policy,
	and store its public and private parts.
	Overwrite existing files.
*/
func (tpm *TPM) CreateKey() {
	var priv, pub []byte
	srk := tpm.GetSRK()

	policy := tpm.GetPCRPolicy()

	key, err := tpm2.Create{
		ParentHandle: srk,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        false,
				SignEncrypt:         true,
			},
			AuthPolicy: policy,
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
	Load key to the TPM from the saved public and private key files.
	Add an authorization session to the key to comply with the PCR policy.
	Return a handle to the loaded key.
*/
func (tpm *TPM) LoadKey() (tpm2.AuthHandle) {
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

	auth := tpm.GetPCRAuth()
	logrus.Debugf("Loaded authorization session")

	return tpm2.AuthHandle{
		Handle: key.ObjectHandle,
		Name:   key.Name,
		Auth:   auth,
	}
}

/*
	Export the loaded public key to base64 DER format
*/
func (tpm *TPM) GetPubKey(hkey tpm2.AuthHandle) (string) {
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
func (tpm *TPM) SignData(data []byte, hkey tpm2.AuthHandle) ([]byte) {
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