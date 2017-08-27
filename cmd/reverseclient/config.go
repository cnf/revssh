package main

/*
import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sort"

	"github.com/cnf/revssh"
	"github.com/cnf/revssh/revutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	keynames = []string{"ssh_host_ecdsa_key", "ssh_host_ed25519_key", "ssh_host_rsa_key"}
)

// A Settings object for the client
type Settings struct {
	revssh.PublicKeyManager
	revssh.PrivateKeyManager
	Remote string

	hostKeys []ssh.Signer
	path     string
	user     string
}

// A Settings object for the client
type ssettings struct {
	Remote string
	path   string

	key  string
	user string
	name string
}

// NewSettings creates and returns a new config object
func NewSettings() *Settings {
	// s := &Settings{}
	cuser, _ := user.Current()
	dpath := fmt.Sprintf("%s/.config/revssh", cuser.HomeDir)
	cdpath, _ := filepath.Abs(dpath)
	name := cuser.Username
	// var path = flag.String("path", cdpath, "configuration path")
	var remote = flag.String("remote", "127.0.0.1:2222", "address:port to connect")
	var username = flag.String("user", name, "ssh user")
	flag.Parse()
	// s.path = *path
	// s.path = cdpath
	// s.Remote = *remote
	// s.user = *username
	return &Settings{
		// revssh.PublicKeyManager:  revutil.NewFilePublicKeyManager(cdpath),
		// revssh.PrivateKeyManager: revutil.NewFilePrivateKeyManager(cdpath),
		path: cdpath, Remote: *remote, user: *username}
	// return s
}

// GetPrivateKeys returns a []ssh.Signer as the ssh server private key
func (s *Settings) GetPrivateKeys() []ssh.Signer {
	log.Println("!!- getting private keys")
	// TODO: THIS IS TEMPORARY! obviously NEVER!! actually run a server with a hardcoded private key.
	// Because it is not very private, is it...

	cpath, err := s.getConfigDir()
	if err != nil {
		log.Panicf("ERROR: can't get config dir: %s", err)
	}
	files, err := ioutil.ReadDir(cpath)
	if err != nil {
		log.Panicf("ERROR: can't get config dir: %s", err)
	}
	sort.Strings(keynames)
	hostKeys := make([]ssh.Signer, 0)
	for fi := range files {
		ki := sort.SearchStrings(keynames, files[fi].Name())
		if ki < len(keynames) && keynames[ki] == files[fi].Name() {
			hostKey, err := revutil.ParsePrivateKeyFile(fmt.Sprintf("%s/%s", s.path, files[fi].Name()))
			// dat, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", s.path, files[fi].Name()))
			if err != nil {
				log.Printf("%+v", err)
				continue
			}
			// hostKey, err := ssh.ParsePrivateKey(dat)
			hostKeys = append(hostKeys, hostKey)
		}
	}
	// 	hostKeyBytes := []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
	// b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
	// QyNTUxOQAAACCbwxBo/3QT+gE3R2U0m71gJvCeLY5wYzaaDBXd6J59HQAAAJDpU9P06VPT
	// 9AAAAAtzc2gtZWQyNTUxOQAAACCbwxBo/3QT+gE3R2U0m71gJvCeLY5wYzaaDBXd6J59HQ
	// AAAEDJR51JvnXwYB6ZDMIHqtE1ke12AfQ/T0Fc5OZ5FOmiRpvDEGj/dBP6ATdHZTSbvWAm
	// 8J4tjnBjNpoMFd3onn0dAAAACXJvb3RAa2FsaQECAwQ=
	// -----END OPENSSH PRIVATE KEY-----`)
	// 	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	// 	if err != nil {
	// 		log.Printf("ERROR: %+v", err)
	// 		return nil
	// 	}
	// 	hostKeys = append(hostKeys, hostKey)
	return hostKeys
}

// GetPublicKeys ...
func (s *Settings) GetPublicKeys(username string) ([]ssh.PublicKey, error) {
	return s.GetAuthorizedKeys(), nil
}

// GetAuthorizedKeys ...
func (s *Settings) GetAuthorizedKeys() []ssh.PublicKey {
	pubKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAgEAvYUpXDQTpAS9Wjtz6Xt6b77U0IxryZXvxbi90AhJqfQ5zQFFrFljO2LnlznKmqolgH6vnwE5G+prksOGt663A7UnxK01HGWtkx/3BkIoDXtg9TKe+MU39OMMCk1MvT4hIjLqIIX0quejmIz89bxRUuipnOyiSGeVHa1f1KykB5UQyK+DJ5iZTtI6/dn2952PaOrZw/gBozz6pc2JUkkE+5iCpuUJgijbVwfPGAh+40W9Vd3S00Uf9mP4QuHH7xpYpgSQC6yk4aUdIkReTpr1dIxOTnJAeSVpSy1KpZdduLx9DC0rtaQxGPcSXMxAp/MsNBuL7r1UKEQeVypg72lQg82ST78L2gA4f4ocg/7xA7gNUSrirhq+QYshRSyV0eBiAe3qGrNAKgJfWeQfYXEMFrWvo8icewmEDfYrBF/TS6wko2AVSuQrYhKvQcNAzN4+L6y0oZHxld2UKCMK3bUTwMoX0qzAZ3ZrFHN6AVmyLwHMsqiLadJgZxFzL5ExVTSxw+ZsKjp4rB1aJ6/J4bbJfMoleATgxQ9J/K8G5hS2q5ooonQq5mn4B+RRm25NlcSlGYjL9x3yG32n1I9RLX7cciZfGyTs4BfkAY63F5YZ1chBIXaFkMG67EZ+i2hx8gU0uPI9UR6WHuQw8E4oObKx2WX9GsX6RthzsM3UyjeVGcc= frank.rosquin@gmail.com"))
	var keys []ssh.PublicKey
	return append(keys, pubKey)
	// return nil, nil
}

// AddKnownHost ...
func (s *Settings) AddKnownHost(hostname string, pubKey ssh.PublicKey) error {
	cpath, err := s.getConfigDir()
	if err != nil {
		log.Panicf("ERROR: can't get config dir: %s", err)
	}
	var list []string
	knownhost := fmt.Sprintln(knownhosts.Line(append(list, hostname), pubKey))
	// err = ioutil.WriteFile(filepath.Join(cpath, "known_hosts"), []byte(knownhost), 0600)
	file, err := os.OpenFile(filepath.Join(cpath, "known_hosts"), os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write([]byte(knownhost))
	if err != nil {
		return err
	}
	return nil
}

// GetKnownHost ...
func (s *Settings) GetKnownHost(hostname string) (pubKey ssh.PublicKey, err error) {
	cpath, err := s.getConfigDir()
	if err != nil {
		log.Panicf("ERROR: can't get config dir: %s", err)
	}
	file, err := os.Open(filepath.Join(cpath, "known_hosts"))
	if err != nil {
		file, err = os.Create(filepath.Join(cpath, "known_hosts"))
		if err != nil {
			return nil, err
		}
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// log.Println(scanner.Text())
		_, hosts, pubKey, _, _, err := ssh.ParseKnownHosts([]byte(scanner.Text()))
		if err != nil {
			return nil, err
		}
		// log.Printf("%s, %s, %s, %s, %s", marker, hosts, pubKey, comment, rest)
		for i := range hosts {
			if hosts[i] == hostname {
				return pubKey, nil
			}
		}
	}
	return nil, nil

	// keyData, err := ssh.ParsePrivateKey(dat)
	// if err != nil {
	// 	return nil, err
	// }
	// return keyData, nil
	// return nil, nil
}

func (s *Settings) getConfigDir() (string, error) {
	err := os.MkdirAll(s.path, os.ModePerm)
	if err != nil {
		return "", err
	}
	return s.path, nil
}

*/
