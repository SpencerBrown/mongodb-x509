// Create and manage X.509 TLS keys and certificates for a MongoDB deployment.
// Driven by a TOML config file. We eschew a whole list of funky options on the command line.
// This command has a set of subcommands. Each subcommand has a corresponding section in the TOML configuration file.

package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"path"
	"time"

	"github.com/pelletier/go-toml"

	"github.com/SpencerBrown/mongodb-x509"
)

// big bucket of parameters for a command
// not all fields have to be set for a given command
type param struct {
	outname   string
	o         []string
	ou        []string
	cn        string
	isca      bool
	expiry    time.Duration
	algorithm mongodb_x509.Algorithm
	keylength int
	password  bool
}

// handler function for subcommands

type handler func(map[string]interface{}, map[string]interface{}, *string) error

// subcommand routing table entry

type srte struct {
	handler_func handler
	rules        map[string]interface{}
}

// routing table for subcommands

var selfsigned_rules = map[string]interface{}{
	"outname":   "root-ca",
	"O":         "MongoDB",
	"OU":        "Certificate Authority",
	"CN":        "",
	"isca":      true,
	"expiry":    365,
	"algorithm": mongodb_x509.RSA,
	"keylength": 2048,
	"password":  false,
}

var routeTable = map[string]srte{
	"selfsigned": {handleSelfSigned, selfsigned_rules},
}

func main() {

	// parse command line arguments

	var toml_file = flag.String("config", "mongodb-x509.toml", "file path/name for TOML format config file")
	var out_dir = flag.String("out", ".", "directory path for certificates and keys")
	flag.Parse()

	// Find the subcommand
	if flag.NArg() == 0 {
		fmt.Println("Missing subcommand on command line")
		return
	}
	subcommand := flag.Args()[0]

	// Validate the subcommand

	my_srte, ok := routeTable[subcommand]
	if !ok {
		fmt.Printf("Invalid subcommand: %s\n", subcommand)
		return
	}
	my_handler_func := my_srte.handler_func
	my_rules := my_srte.rules

	// find the section in the config file for this subcommand
	// and convert it to a map[string]interface{}

	// Load the config file
	toml_config, err := toml.LoadFile(*toml_file)
	if err != nil {
		fmt.Printf("Failed to parse config file: %v\n", err)
		return
	}

	var subtree *toml.TomlTree

	// validate that we have a subtree corresponding to the given section
	xsubtree := toml_config.Get(subcommand)
	if xsubtree == nil {
		fmt.Printf("parseConfig: Config file must have [%s] section\n", subcommand)
		return
	}
	switch xsubtree.(type) {
	case *toml.TomlTree:
		subtree = xsubtree.(*toml.TomlTree)
	default:
		fmt.Printf("parseConfig: Config file must have [%s] section\n", subcommand)

	}
	tree_map := subtree.ToMap()

	err = my_handler_func(tree_map, my_rules, out_dir)
	if err != nil {
		fmt.Printf("Error running %s: %v\n", subcommand, err)
		return
	}
}

func handleSelfSigned(tree_map map[string]interface{}, rules map[string]interface{}, dir *string) error {

	ss_config, err := parseConfig(tree_map, rules)
	if err != nil {
		return fmt.Errorf("handleSelfSigned: Invalid config file: %v", err)
	}
	name := ss_config.outname

	// Generate private/public key pair
	priv, err := mongodb_x509.GenerateKey(ss_config.keylength, ss_config.algorithm)
	if err != nil {
		return fmt.Errorf("handleSelfSigned: Failed to generate public/private key pair: %v", err)
	}

	// Generate self-signed root certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(ss_config.expiry)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("handleSelfSigned: failed to generate serial number: %v", err)
	}

	root_template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       ss_config.o,
			OrganizationalUnit: ss_config.ou,
			CommonName:         ss_config.cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IsCA:                  ss_config.isca,
		BasicConstraintsValid: true,
	}
	if ss_config.isca {
		root_template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &root_template, &root_template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("foot: failed to create %s certificate: %v", name, err)
	}

	// Write root CA certificate

	err = mongodb_x509.WriteCert(path.Join(*dir, "tls-"+name), name, derBytes)
	if err != nil {
		return fmt.Errorf("handleSelfSigned: Failed to write %s certificate file: %v", name, err)
	}

	// Write root CA private key

	err = mongodb_x509.WriteKey(path.Join(*dir, "tls-"+name), name+"-key", priv, ss_config.password)
	if err != nil {
		return fmt.Errorf("handleSelfSigned: Failed to write %s private key file: %v", name, err)
	}

	return nil
}

// Parse a section of the TOML config file according to a map of default rules. Return a param structure with all the proper values and defaults.

func parseConfig(tree_map map[string]interface{}, rules map[string]interface{}) (*param, error) {
	var cf param

	// fill in default values from the rules map
	for key, default_value := range rules {
		switch key {
		case "outname":
			cf.outname = default_value.(string)
		case "O":
			cf.o = make([]string, 1)
			cf.o[0] = default_value.(string)
		case "OU":
			cf.ou = make([]string, 1)
			cf.ou[0] = default_value.(string)
		case "CN":
			cf.cn = default_value.(string)
		case "isca":
			cf.isca = default_value.(bool)
		case "expiry":
			cf.expiry = time.Duration(default_value.(int)) * time.Hour
		case "algorithm":
			cf.algorithm = default_value.(mongodb_x509.Algorithm)
		case "keylength":
			cf.keylength = default_value.(int)
		case "password":
			cf.password = default_value.(bool)
		default:
			panic("Something wrong in default rules!")
		}
	}

	// fill in user specified values
	for item, value := range tree_map {
		_, found_item := rules[item]

		if found_item {
			switch item {
			case "outname":
				switch value.(type) {
				case string:
					cf.outname = value.(string)
				default:
					return nil, fmt.Errorf("Key %q should have a string value", item)
				}
			case "O":
				switch value.(type) {
				case string:
					cf.o = make([]string, 1)
					cf.o[0] = value.(string)
				default:
					return nil, fmt.Errorf("Key %q should have a string value", item)
				}
			case "OU":
				switch value.(type) {
				case string:
					cf.ou = make([]string, 1)
					cf.ou[0] = value.(string)
				default:
					return nil, fmt.Errorf("Key %q should have a string value", item)
				}
			case "CN":
				switch value.(type) {
				case string:
					cf.cn = value.(string)
				default:
					return nil, fmt.Errorf("Key %q should have a string value", item)
				}
			case "isca":
				switch value.(type) {
				case bool:
					cf.isca = value.(bool)
				default:
					return nil, fmt.Errorf("Key %q should have a true/false value", item)
				}
			case "expiry":
				switch value.(type) {
				case int64:
					//TODO check for valid expiry values
					cf.expiry = time.Duration(value.(int64)) * time.Hour
				default:
					return nil, fmt.Errorf("Key %q should have a numeric value", item)
				}
			case "algorithm":
				switch value.(type) {
				case string:
					switch value.(string) {
					case "RSA":
						cf.algorithm = mongodb_x509.RSA
					case "ECDSA":
						cf.algorithm = mongodb_x509.ECDSA
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
			case "password":
				switch value.(type) {
				case bool:
					cf.password = value.(bool)
				default:
					return nil, fmt.Errorf("Key %q should have a true/false value", item)
				}
			default:
				panic(fmt.Sprintf("Something wrong in config_rule! %q\n", item))
			}
		} else {
			return nil, fmt.Errorf("Unknown key %q in config file", item)
		}
	}
	return &cf, nil
}
