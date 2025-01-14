package main

/*
	Create a signing key (ECC), seal it to the TPM
	following a policy matching the selected PCRs,
	and store its public and (sealed) private parts
	into two files. Overwrite existing files.
*/
func createKey(pcr string) {
	
}

/*
	Load key to the TPM from the saved
	public and private key files.
	Return a handle to the loaded key.
*/
func loadKey() (int) {
	
}

/*
	Get the PEM certificate associated to
	the loaded public key.
*/
func getPubCert(hkey int) (string) {
	
}

/*
	Sign binary data using the loaded signing key.
*/
func signData(data []byte, hkey int) ([]byte) {
	
}