package revssh

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

type requestHandler func(srv *Server, sshConn *ssh.ServerConn, req *ssh.Request)

// ReverseClientData contains the ssh reverse channel data,
// as per RFC 4254 Section 4
type ReverseClientData struct {
	Version       string   // Implementation version.
	Hostname      string   // Hostname to register.
	Username      string   // Username to register the ssh keys under.
	PublicKeysHex []string // list of ssh Publickeys, in hex. (for marshalling purposes)
}

func reverseClientRequestHandler(srv *Server, sshConn *ssh.ServerConn, req *ssh.Request) {
	log.Printf("Reverse client registration received for client: %s", sshConn.User())
	d := &ReverseClientData{}
	if err := ssh.Unmarshal(req.Payload, d); err != nil {
		log.Printf("%+v", err)
	}
	sessionKey := srv.GetSession(sshConn.SessionID())
	// TODO: normalize hostname / port
	err := srv.Settings.IsKnownHost(fmt.Sprintf("%s:22", d.Hostname), sshConn.RemoteAddr(), sessionKey)
	if err != nil {
		log.Printf("%+v", err)
		req.Reply(false, []byte("v1"))
		return
	}

	// if knownKey == nil {
	// 	_ = srv.Settings.AddKnownHost(d.Hostname, sessionKey)
	// }
	// if !revutil.KeysEqual(sessionKey, knownKey) && knownKey != nil {
	// 	log.Printf("hostname already registered")
	// 	req.Reply(false, []byte("v1"))
	// }
	err = srv.NewReverseClient(sshConn, d)
	if err != nil {
		log.Printf("%+v", err)
		req.Reply(false, []byte("v1"))
		return
	}
	req.Reply(true, []byte("v1"))
}

func keepaliveRequestHandler(srv *Server, sshConn *ssh.ServerConn, req *ssh.Request) {
	// log.Printf("keepalive request from %s", sshConn.User())
	req.Reply(true, nil)
}
