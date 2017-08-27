/*
Package revutil supplies various utilities needed by revssh.
*/
package revutil

import (
	"crypto/subtle"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk ssh.PublicKey) bool {
	//avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return (subtle.ConstantTimeCompare(a, b) == 1)
	// return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}

// ParsePrivateKeyFile takes a path, and returns an ssh.Signer from that file, or an error.
func ParsePrivateKeyFile(path string) (ssh.Signer, error) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keyData, err := ssh.ParsePrivateKey(dat)
	if err != nil {
		return nil, err
	}
	return keyData, nil
}

// AppendLine appends a line to a file, creating it if it doesn't exist.
func AppendLine(filepath, content string) error {
	log.Printf("Writing to: %s", filepath)
	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	if _, err = f.WriteString("\n" + content); err != nil {
		return err
	}
	return nil
}
