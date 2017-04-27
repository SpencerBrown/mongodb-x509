package mongodb_x509

import (
	"fmt"

	"golang.org/x/crypto/ssh/terminal"
)

// GetPassword: get a password securely from the user via the terminal, characters are not echoed
//    identity: a prefix for the user to understand what he is entering a password for
//    doublecheck: whether to have the user enter the same password twice
//    return: password as []byte

func GetPassword(identity string, doublecheck bool) ([]byte, error) {

	matched_inputs := false
	var pwd, pwd2 []byte
	var err error
	for !matched_inputs {
		fmt.Print("Enter passphrase for ", identity, ": ")
		pwd, err = terminal.ReadPassword(0)
		if err != nil {
			return nil, fmt.Errorf("\nError reading passphrase: %v", err)
		}
		matched_inputs = true // assume they match for the moment
		if doublecheck {
			fmt.Print("\nEnter passphrase again: ")
			pwd2, err = terminal.ReadPassword(0)
			if err != nil {
				return nil, fmt.Errorf("\nError reading passphrase: %v", err)
			}
			if len(pwd) == len(pwd2) {
				for i := 0; i < len(pwd); i++ {
					if pwd[i] != pwd2[i] {
						matched_inputs = false
					}
				}
			} else {
				matched_inputs = false // not the same length
			}
		}
		fmt.Println()
		if !matched_inputs {
			fmt.Print("\n*** Passphrases do not match ***\n\n")
		}
	}
	return pwd, nil
}
