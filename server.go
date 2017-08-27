package revssh

import (
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/cnf/revssh/revutil"

	"golang.org/x/crypto/ssh"
)

// A ServerSettingsHandler takes care of abstracting settings and config data.
type ServerSettingsHandler interface {
	KeyManager
}

// A Server represents an instance of an ssh server.
type Server struct {
	ReverseClientList
	Addr         string // listen address
	MaxAuthTries int    // maximum auth retries a client can do. See ssh.ServerConfig MaxAuthTries.
	AllowReverse bool   // does this server register reverseclients?
	Settings     ServerSettingsHandler
	// IsKnownHost       IsKnownHost
	// GetPrivateKeys    GetPrivateKeys
	// GetAuthorizedKeys GetAuthorizedKeys

	version         string
	requestHandlers map[string]requestHandler
	channelHandlers map[string]channelHandler
}

// NewServer returns a new ssh Server instance.
func NewServer() *Server {
	return &Server{
		Addr:         ":22",
		MaxAuthTries: 0,
	}
}

// ServeTCP opens a TCP socket and starts an sshd server on it.
func (srv *Server) ServeTCP() error {
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	defer l.Close()
	var tempDelay time.Duration
	for {
		conn, e := l.Accept()
		if e != nil {
			// TODO: refactor
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		go srv.handleConn(conn)
	}
}

// ServeChan accepts incoming connections on an ssh channel, and serves an
// ssh server on them.
func (srv *Server) ServeChan(chans <-chan ssh.NewChannel) error {
	for newChannel := range chans {
		channel, reqs, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			// continue
			return nil
		}
		go ssh.DiscardRequests(reqs)
		log.Printf("serving sshd on channel")
		conn := NewSSHChannelConn(channel)
		srv.handleConn(conn)
		log.Printf("closing sshd on channel")
	}
	return nil
}

// ServerVersionString returns a proper ssh server string as per RFC 4253 Section 4.2
func (srv *Server) ServerVersionString() string {
	if srv.version == "" {
		srv.version = VERSION
	}
	if strings.HasPrefix(srv.version, RFC425342) {
		return srv.version
	}
	return RFC425342 + srv.version
}

// return an ssh.ServerConfig object with all settings applied.
func (srv *Server) config() *ssh.ServerConfig {
	srv.requestHandlers = map[string]requestHandler{
		"keepalive@openssh.com": keepaliveRequestHandler,
		// "reverse-client":        reverseClientRequestHandler,
	}
	if srv.AllowReverse {
		srv.requestHandlers["reverse-client"] = reverseClientRequestHandler
	}
	srv.channelHandlers = map[string]channelHandler{
		"session":      sessionChannelHandler,
		"direct-tcpip": directTcpipChannelHandler,
	}

	config := &ssh.ServerConfig{}
	// TODO: cleanup
	for _, signer := range srv.Settings.GetPrivateKeys() {
		if signer == nil {
			continue
		}
		config.AddHostKey(signer)
	}

	config.MaxAuthTries = srv.MaxAuthTries
	config.ServerVersion = srv.ServerVersionString()
	config.PublicKeyCallback = srv.publicKeyCallback
	config.AuthLogCallback = srv.authLogCallback
	return config
}

func (srv *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	log.Printf("Accepting connection from %s", conn.RemoteAddr())
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, srv.config())
	if err != nil {
		log.Printf("handleconn: %+v", err)
		// TODO: trigger event callback
		return
	}
	go srv.requestsHandler(sshConn, reqs)
	for ch := range chans {
		log.Printf(" Channel Handler for: %+v", ch.ChannelType())
		handler, found := srv.channelHandlers[ch.ChannelType()]
		if !found {
			ch.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		go handler(srv, sshConn, ch)
	}
	srv.RemoveReverseClient(sshConn.SessionID())
	srv.RemoveSession(sshConn.SessionID())
	log.Printf("Closing connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
}

func (srv *Server) requestsHandler(sshConn *ssh.ServerConn, reqs <-chan *ssh.Request) {
	for req := range reqs {
		handler, found := srv.requestHandlers[req.Type]
		if !found {
			log.Printf("no request handler found for '%s'", req.Type)
			req.Reply(false, []byte("request type not found"))
			continue
		}
		go handler(srv, sshConn, req)
	}

}

func (srv *Server) publicKeyCallback(remoteConn ssh.ConnMetadata, remoteKey ssh.PublicKey) (*ssh.Permissions, error) {
	// TODO: audit this bit.
	log.Printf("key for %s: %s", remoteConn.User(), ssh.FingerprintSHA256(remoteKey))
	// lookup in keylist from reverseclients
	rckeys, _ := srv.ReverseClientList.GetPublicKeys(remoteConn.User())
	keysMatch := false
	for i := range rckeys {
		if revutil.KeysEqual(rckeys[i], remoteKey) {
			log.Println("rev key found")
			keysMatch = true
			break
		}
	}

	// lookup in local authorized_keys file
	localkeys := srv.Settings.GetAuthorizedKeys()
	for i := range localkeys {
		if revutil.KeysEqual(localkeys[i], remoteKey) {
			log.Println("local key found")
			keysMatch = true
			break
		}
	}

	if !keysMatch {
		return nil, errors.New("no matching key found")
	}
	perm := &ssh.Permissions{
		Extensions: map[string]string{
			"username": remoteConn.User(),
		},
	}
	srv.AddSession(remoteConn.SessionID(), remoteKey)
	return perm, nil
}

func (srv *Server) authLogCallback(conn ssh.ConnMetadata, method string, err error) {
	if err == nil {
		switch method {
		case "publickey":
			log.Printf("AUTH: user %s (%s) from %s authenticated with publickey", conn.User(), conn.ClientVersion(), conn.RemoteAddr())
		default:
			log.Printf("AUTH: for %s from %s -> %+v -> %+v", conn.User(), conn.RemoteAddr(), method, err)
		}
		return
	}
	switch err.Error() {
	case "no auth passed yet":
		log.Printf("AUTH: request from %s (%s) at %s", conn.User(), conn.ClientVersion(), conn.RemoteAddr())
	case "no matching key found":
		log.Printf("AUTH: request DENIED from %s (%s) at %s", conn.User(), conn.ClientVersion(), conn.RemoteAddr())
	default:
		log.Printf("AUTH REJECTED: for %s from %s -> %+v -> %+v", conn.User(), conn.RemoteAddr(), method, err)
	}
}
