<p align="center"><img height=150px src="res/ultraqr.png"/></p>

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
- Create a new signing key: `ultraqr -init [-device DEVICE] [-key KEY_PATH] [-pcr PCRs]`<br/>
UltraQR creates a new signing key (ECC P-256, SHA256, in the owner hierarchy) bound to an authorization policy based on PCRs states (by default, PCRs 0,2,4,7,8,9).

- Enroll a new verification device: `ultraqr -enroll [-device DEVICE] [-key KEY_PATH] [-out OUT_PATH]`<br/>
UltraQR exports the public part of the signing key in DER form and embeds it into the generated QR code.

- Verify the states of the PCR: `ultraqr -verify [-device DEVICE] [-key KEY_PATH] [-pcrs PCRs] [-out OUT_PATH] [-challenge CHALLENGE]`<br/>
UltraQR loads the signing key, satisfies the authorization policy and signs the current timestamp and embeds the signed data into the generated QR code.
To attest that the PCR values match those at initialization, you MUST:
    - verify that the signature is valid for the SHA256 sum of the timestamp using the previously enrolled public key (attest that the authorization policy has been satisfied, meaning that you are using the same TPM and that PCR states match those at initialization)
    - check that the timestamp matches the current date-time (attest that the authorization policy has been satisfied *now*, which prevents replay attacks of the QR code)

### Advanced usage
- If the `-challenge` parameter is specified during verification, the verification process will sign the provided challenge instead of the current timestamp. Using robust challenges is recommended if the device may have been compromised in the past while the PCRs were in expected states (as the attacker may have satisfied the PCR authorization policy in order to sign arbitrary timestamps for a future bootchain compromise).

### Command references
```
$ ultraqr --help
Usage of ultraqr:
  -challenge string
        Custom challenge to sign during verification (optional)
  -device string
        Path to the TPM device to use (default "/dev/tpm0")
  -enroll
        Enroll a new verifier device
  -init
        Initialize UltraQR with a new signing key
  -key string
        Path to store the signing key public and private TPM parts (default "/etc/ultraqr")
  -out string
        Output filename to save the generated QR code as a png image (optional)
  -pcrs string
        Selected PCRs for the authorization policy (default "0,2,4,7,8,9")
  -verbose
        Use verbose logging
  -verify
        Verify measured boot state
```

NB: `ultraqr` may require root permissions to interact with your TPM device

## Credits
UltraQR is largely inspired by [UltraBlue](https://github.com/ANSSI-FR/ultrablue) (User-friendly Lightweight TPM Remote Attestation over Bluetooth), which provides full TPM remote attestation over BLE.