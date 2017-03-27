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
	"path"
)

type m_config struct {
	o         []string
	ou        []string
	algorithm algor
	keylength int
	expiry    time.Duration
}

type algor int
const (
	RSA algor = iota
	ECDSA
)

type m_config_rules struct {
	key  string
	def  interface{}
}

func main() {

	toml_config, err := toml.LoadFile("mongodb-x509.toml")
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	// root CA certificate configuration and defaults
	root_config_rules := []m_config_rules{
		{"O", "MongoDB" },
		{"OU", "Certificate Authority" },
		{"algorithm", RSA },
		{"keylength", 2048 },
		{"expiry", 365 },
	}

	root_tree := toml_config.Get("root")
	if root_tree == nil {
		log.Fatal("Config file must have [root] section")
	}
	switch root_tree.(type) {
	case *toml.TomlTree:
	default:
		log.Fatal("Config file must have [root] section")

	}
	root_config, err := get_m_config(root_tree.(*toml.TomlTree), root_config_rules)
	if err != nil {
		log.Fatalf("Invalid config file: %v", err)
	}


	fmt.Println(root_config)

	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, root_config.keylength)
	if err != nil {
		log.Fatalf("Failed to generate private key: %s", err)
	}

	// Generate self-signed root certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(root_config.expiry)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	root_template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       root_config.o,
			OrganizationalUnit: root_config.ou,
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
	root_path := path.Join("tls-root-ca")
	root_path_private := path.Join(root_path, "private")
	err = os.MkdirAll(root_path_private, 0755)
	if err != nil {
		log.Fatalf("Failed to create directory for root CA certificate: %s", err)
	}
	root_ca_path := path.Join(root_path, "root-ca.pem")
	certOut, err := os.Create(root_ca_path)
	if err != nil {
		log.Fatalf("Failed to open root certificate file for writing: %s", err)
	}
	certpemblock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	pem.Encode(certOut, certpemblock)
	certOut.Close()
	log.Print("Written root certificate")

	// Write private key for root CA certificate
	root_key_path := path.Join(root_path_private, "root-ca-key.pem")
	keyOut, err := os.OpenFile(root_key_path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key file for writing: %s", err)
	}
	keypemblock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	pem.Encode(keyOut, keypemblock)
	keyOut.Close()
	log.Print("Private key written")

}

func get_m_config(tree *toml.TomlTree, rules []m_config_rules) (*m_config, error) {
	var cf m_config
	tree_map := tree.ToMap()

	// fill in default values
	for _, rule := range rules {
		switch rule.key {
		case "O":
			cf.o = append(cf.o, rule.def.(string))
		case "OU":
			cf.ou = append(cf.ou, rule.def.(string))
		case "algorithm":
			cf.algorithm = rule.def.(algor)
		case "keylength":
			cf.keylength = rule.def.(int)
		case "expiry":
			cf.expiry = time.Duration(rule.def.(int)) * time.Hour
		}
	}

	// fill in user specified values
	for item, value := range tree_map {
		found_item := false
		for _, rule := range rules {
			if rule.key == item {
				found_item = true
				switch item {
				case "O":
					switch value.(type) {
					case string:
						 cf.o = append(cf.o, value.(string))
					default:
						return nil, fmt.Errorf("Key %q should have a string value", item)
					}
				case "OU":
					switch value.(type) {
					case string:
						cf.ou = append(cf.ou, value.(string))
					default:
						return nil, fmt.Errorf("Key %q should have a string value", item)
					}
				case "algorithm":
					switch value.(type) {
					case string:
						switch value.(string) {
						case "RSA":
							cf.algorithm = RSA
						case "ECDSA":
							cf.algorithm = ECDSA
						default:
							return nil, fmt.Errorf("algorithm must be \"RSA\" or \"ECDSA\", was %q", value.(string))
						}
					default:
						return nil, fmt.Errorf("Key %q should have a string value", item)
					}
				case "keylength":
					switch value.(type) {
					case int64:
						//TODO check for valid keylength values
						cf.keylength = int(value.(int64))
					default:
						return nil, fmt.Errorf("Key %q should have a numeric value", item)
					}
				case "expiry":
					switch value.(type) {
					case int64:
						//TODO check for valid expiry values
						cf.expiry = time.Duration(value.(int64)) * time.Hour
					default:
						return nil, fmt.Errorf("Key %q should have a numeric value", item)
					}
				default:
					log.Fatalf("Something wrong in m_config_rules! %q", item)
				}
			}
		}
		if !found_item {
			return nil, fmt.Errorf("Unknown key %q in config file", item)
		}
	}
	return &cf, nil
}
