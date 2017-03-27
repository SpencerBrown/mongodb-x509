package main

import (
	"fmt"
	"github.com/pelletier/go-toml"
	"crypto/rsa"
	"crypto/rand"
	"os"
	"encoding/pem"
	"crypto/x509"
	"time"
	"math/big"
	"log"
	"crypto/x509/pkix"
)

func main() {

	config, err := toml.LoadFile("mongodb-x509.toml")
	if err != nil {
		fmt.Println("Error ", err.Error())
		return
	}

	rootconfig := config.Get("root").(*toml.TomlTree)
	rootOraw := rootconfig.Get("O").(string)
	rootO := make([]string, 1)
	rootO[0] = rootOraw
	rootOUraw := rootconfig.Get("OU").(string)
	rootOU := make([]string, 1)
	rootOU[0] = rootOUraw
	rootalgorithm := rootconfig.Get("algorithm").(string)
	rootkeylength := rootconfig.Get("keylength").(int64)
	rootexpiryraw := rootconfig.Get("expiry").(int64)
	rootexpiry := time.Duration(rootexpiryraw) * time.Hour

	fmt.Println(rootO, rootOU, rootalgorithm, rootkeylength, rootexpiry)

	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, int(rootkeylength))
	if err != nil {
		log.Fatalf("Failed to generate private key: %s", err)
	}

	// Generate self-signed root certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(rootexpiry)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	root_template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       rootO,
			OrganizationalUnit: rootOU,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &root_template, &root_template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("failed to create root certificate: %s", err)
	}

	// Write root CA certificate
	certOut, err := os.Create("root-ca.pem")
	if err != nil {
		log.Fatalf("Failed to open root certificate file for writing: %s", err)
	}
	certpemblock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	pem.Encode(certOut, certpemblock)
	certOut.Close()
	log.Print("Written root certificate")

	// Write private key for root CA certificate
	keyOut, err := os.OpenFile("root-ca-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key file for writing: %s", err)
	}
	keypemblock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	pem.Encode(keyOut, keypemblock)
	keyOut.Close()
	log.Print("Private key written")

}

/*
[root]
O = "MongoDB"
OU = "Certificate Authority"
algorithm = "RSA"
keylength = 2048
# expiration in days
expiry = 1000
 */
