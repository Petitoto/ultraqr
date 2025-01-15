<p align="center"><img height=150px src="images/ultraqr.png"/></p>

# UltraQR
UltraQR (User-friendly Lightweight TPM Remote Attestation over QR code) is a solution that enables individual users to attest TPM PCR values using their mobile phones. Its primary goal is to verify the bootchain state of a potentially compromised host from a trusted host simply by scanning a QR code.

## Setup
UltraQR is automatically built by Github Actions on [release](https://github.com/Petitoto/ultraqr/releases).

You can also clone the repository and build the project yourself:
```
git clone https://github.com/Petitoto/ultraqr.git
cd ultraqr/ultraqr
go build .
sudo install ultraqr /usr/local/bin
```

## How to use
### Verification process
- Create a new signing key: `ultraqr -init`<br/>
UltraQR creates a new signing key (ECC P-256, SHA256) and seals it to the TPM using the default primary SRK (ECC) and the following PCR states: 0,2,4,8,9.

- Enroll a new verification device: `ultraqr -enroll`<br/>
UltraQR exports the public part of the signing key in DER form and embeds it into the generated QR code.

- Verify the states of the PCR: `ultraqr -verify`<br/>
UltraQR unseals the signing key, signs the current timestamp and embeds the signed data into the generated QR code.
To attest that the PCR values match those at initialization, you MUST:
    - verify that the signature match the timestamp using the previously enrolled public key (attest that the signing key has been successfully unsealed, meaning that you are using the same TPM and that PCR states match the ones at initialization)
    - check that the timestamp corresponds to the current date-time (attest that the signing key has been successfully unsealed *now*, which prevents replay attacks of the QR code)

### Command references
```
$ ultraqr --help
Usage of ultraqr:
  -device string
        Path to the TPM device to use (default "/dev/tpm0")
  -enroll
        Enroll a new verifier device
  -init
        Initialize UltraQR with a new signing key
  -verbose
        Use verbose logging
  -verify
        Verify measured boot state
```

NB: `ultraqr` may require root permissions to interact with your TPM device

## Credits
UltraQR is largely inspired by [UltraBlue](https://github.com/ANSSI-FR/ultrablue) (User-friendly Lightweight TPM Remote Attestation over Bluetooth), which provides full TPM remote attestation over BLE.