
package mongodb_x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
)

type Algorithm int

const (
	RSA Algorithm = iota
	ECDSA
)

// Generate a private/public key pair, given the key length and the desired algorithm
// TODO support ECDSA, currently that option is ignored

func GenerateKey(keylength int, algorithm Algorithm) (*rsa.PrivateKey, error) {

	switch algorithm {
	case RSA:
		priv, err := rsa.GenerateKey(rand.Reader, keylength)
		if err != nil {
			return nil, fmt.Errorf("GenerateKey: Failed to generate key pair: %v", err)
		}
		return priv, nil
	case ECDSA:
		return nil, errors.New("ECDSA not yet implemented")
	default:
		panic("Something wrong with algorithm!")
	}
}

// Write an X.509 certificate to a file in a directory

func WriteCert(dir string, filename string, cert []byte) error {

	// Write  X.509 certificate to a file
	file_path := path.Join(dir)
	err := os.MkdirAll(file_path, 0755)
	if err != nil {
		return fmt.Errorf("WriteCert: Failed to create directory %s for certificate: %v", file_path, err)
	}
	cert_path := path.Join(file_path, filename+".pem")
	certOut, err := os.Create(cert_path)
	if err != nil {
		return fmt.Errorf("WriteCert: Failed to open certificate file %s for writing: %v", cert_path, err)
	}
	certpemblock := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	pem.Encode(certOut, certpemblock)
	certOut.Close()
	return nil
}

// Write a private key to a file in a directory. If a password is desired to encrypt the key, get one from the user.

func WriteKey(dir string, filename string, priv *rsa.PrivateKey, want_password bool) error {

	// Encode private key into PEM, encrypted if needed
	priv_pem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	if want_password {
		pwd, err := GetPassword("private key", true)
		if err != nil {
			return fmt.Errorf("WriteKey: Unable to get passphrase: %v", err)
		}
		priv_pem, err = x509.EncryptPEMBlock(rand.Reader, priv_pem.Type, priv_pem.Bytes, pwd, x509.PEMCipherAES128)
	}

	// Write private key to a file
	file_path := path.Join(dir, "private")
	err := os.MkdirAll(file_path, 0755)
	if err != nil {
		return fmt.Errorf("WriteKey: Failed to create directory %s for key: %v", file_path, err)
	}
	key_path := path.Join(file_path, filename+".pem")
	keyOut, err := os.OpenFile(key_path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("WriteKey: Failed to open key file for writing: %v", err)
	}
	pem.Encode(keyOut, priv_pem)
	keyOut.Close()
	return nil
}
