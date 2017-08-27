package revssh

import (
	"bytes"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

/*
ge moest me uw session id de pubkey kunnen opzoeken bij het openen van een nieuw reverse channel
zodat ge kon zien of die zich wel me die naam mocht registreren
of nie al een andere host me een andere pubkey da al had gedaan
ge ging bij het starten van uw connection de NewConnectionID(...) oproepen met de sessionid en pubkey, daarna bij het registreren van een hostname de NewHostname met de hostnaem en de session id
en daarin checken of die pubkey die hostname mocht registreren
*/

// A ReverseClientHandler holds all the metadata of a reverse client connection.
// This is part of the ReverseClientList
type ReverseClientHandler struct {
	SSHConn  ssh.Conn        // ssh connection from a reverseclient.
	Hostname string          // Hostname for this reverseclient.
	Username string          // Username this reverseclient will accept.
	KeyList  []ssh.PublicKey // list of ssh.PublicKeys for this reverseclient.
	// sync.RWMutex
}

// A ReverseClientList maintains a list of active reverse clients, and
// provides lookup mechanisms.
type ReverseClientList struct {
	reverseClients []*ReverseClientHandler
	sessions       map[string]ssh.PublicKey
	sync.RWMutex
}

// NewReverseClient registers a new reverse client to the list, and logs which
// pubkey was used to do so. If a previous entry for this hostname exists with
// the same pubkey, it is overwritten. If a previous entry for this hostname
// exists with another pubkey, the registration is rejected.
func (rcl *ReverseClientList) NewReverseClient(sshConn *ssh.ServerConn, data *ReverseClientData) error {
	// TODO: add known_hosts working
	// lookup van session ID naar public key
	// lookup if public key can register hostname
	// replace existing ssh conn if one exists
	rc := &ReverseClientHandler{
		Hostname: strings.ToLower(data.Hostname),
		Username: data.Username,
		SSHConn:  sshConn,
	}
	for i := range data.PublicKeysHex {
		kb, err := hex.DecodeString(data.PublicKeysHex[i])
		if err != nil {
			continue
		}
		key, err := ssh.ParsePublicKey(kb)
		if err != nil {
			continue
		}
		rc.KeyList = append(rc.KeyList, key)
	}
	rcl.Lock()
	defer rcl.Unlock()
	log.Printf("Adding %s as a reverse client", rc.Hostname)
	rcl.reverseClients = append(rcl.reverseClients, rc)
	return nil
}

// RemoveReverseClient removes a reverseclient from the list.
func (rcl *ReverseClientList) RemoveReverseClient(sessionID []byte) error {
	rcl.Lock()
	defer rcl.Unlock()
	var tmparr []*ReverseClientHandler
	for i := range rcl.reverseClients {
		if rcl.reverseClients[i] == nil {
			log.Printf("WHY IS THIS revclientlist  NIL? %+v", sessionID)
			continue
		}
		if bytes.Equal(rcl.reverseClients[i].SSHConn.SessionID(), sessionID) {
			log.Printf("Removing %s as a reverse client", rcl.reverseClients[i].Hostname)
			continue
			// rcl.reverseClients = append(rcl.reverseClients[:i], rcl.reverseClients[i+1:]...)
		}
		tmparr = append(tmparr, rcl.reverseClients[i])

	}
	rcl.reverseClients = tmparr
	return nil
}

// GetReverseClient returns a reverseclient from a hostname and username.
func (rcl *ReverseClientList) GetReverseClient(hostname string, username string) (*ReverseClientHandler, error) {
	rcl.RLock()
	defer rcl.RUnlock()
	for _, rc := range rcl.reverseClients {
		if rc.Hostname == strings.ToLower(hostname) && rc.Username == username {
			return rc, nil
		}
	}
	return nil, errors.New("no reverse connection found")
}

// GetPublicKeys returns a list of ssh.PublicKeys registered for a specific
// username by reverseclients.
func (rcl *ReverseClientList) GetPublicKeys(username string) ([]ssh.PublicKey, error) {
	// func (rcl *ReverseClientList) GetPublicKeys(remoteKey ssh.PublicKey) error {
	rcl.RLock()
	defer rcl.RUnlock()
	var keys []ssh.PublicKey
	for ci := range rcl.reverseClients {
		if rcl.reverseClients[ci].Username == username {
			keys = append(keys, rcl.reverseClients[ci].KeyList...)
		}
	}
	return keys, nil
}

// AddSession registers a session to a certain public key.
func (rcl *ReverseClientList) AddSession(sessionID []byte, key ssh.PublicKey) error {
	rcl.Lock()
	defer rcl.Unlock()
	if rcl.sessions == nil {
		rcl.sessions = make(map[string]ssh.PublicKey)
	}
	rcl.sessions[hex.EncodeToString(sessionID)] = key
	return nil
}

// GetSession returns the ssh.PublicKey used by a session.
func (rcl *ReverseClientList) GetSession(sessionID []byte) ssh.PublicKey {
	rcl.RLock()
	defer rcl.RUnlock()
	return rcl.sessions[hex.EncodeToString(sessionID)]
}

// RemoveSession removes a session from the lookup table.
func (rcl *ReverseClientList) RemoveSession(sessionID []byte) error {
	rcl.Lock()
	defer rcl.Unlock()
	IDString := hex.EncodeToString(sessionID)
	delete(rcl.sessions, IDString)
	return nil
}
