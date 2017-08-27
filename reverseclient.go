package revssh

import (
	"encoding/hex"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jpillora/backoff"

	"golang.org/x/crypto/ssh"
)

// A ClientSettingsHandler abstracts client settings from the underlying
// mechanics of retrieving and setting them.
type ClientSettingsHandler interface {
	KeyManager
	Remote() string
	User() string
	Hostname() string
}

// A ReverseClient represents an instance of a reverse client.
type ReverseClient struct {
	// Username used for this client connection.
	// Also defines what username will be accepted for incoming connections.
	// Username string
	// Remote server to connect to.
	// Remote string
	// Hostname to register yourself as.
	// Hostname string
	Settings ClientSettingsHandler

	version     string
	authMethods []ssh.AuthMethod
}

// NewReverseClient returns a ReverseClient instance, with some sane defaults.
func NewReverseClient() *ReverseClient {
	rc := &ReverseClient{}
	// if rc.Username == "" {
	// 	rc.Username = "revssh"
	// }
	return rc
}

// Connect to a server.
// Connections will be retried with a backoff mechanism.
// If the error is unrecoverable (no ssh keys set etc), this wil exit with
// an error.
func (rc *ReverseClient) Connect() error {
	if rc.Settings.Remote() == "" {
		return errors.New("no remote specified")
	}
	// if rc.Hostname == "" {
	// 	hostname, err := os.Hostname()
	// 	if err != nil || hostname == "" {
	// 		return errors.New("could not get hostname")
	// 	}
	// 	rc.Hostname = hostname
	// }
	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Jitter: true,
	}
	for {
		conn, err := ssh.Dial("tcp", rc.Settings.Remote(), rc.config())
		if err != nil {
			if strings.HasSuffix(err.Error(), "key not found") {
				return err
			}
			d := b.Duration()
			log.Printf("%s, reconnecting in %s", err, d)
			time.Sleep(d)
			continue
		}
		log.Printf("Connected to %s", conn.RemoteAddr())
		b.Reset()
		go keepAlive(conn)
		var once sync.Once
		defer once.Do(func() { conn.Close() })
		err = rc.Reverse(conn)
		if err != nil {
			if strings.HasSuffix(err.Error(), "reverse request rejected") {
				return err
			}
			log.Printf("%+v", err)
		}
		once.Do(func() { conn.Close() })
	}
}

// Reverse the connection, sending a reverse-client global request to the server
// to register ourselves as a reverse client.
// Listen to incoming `reverse` channel requests, and bind an sshd to this
// channel.
func (rc *ReverseClient) Reverse(conn *ssh.Client) error {
	pkdata := rc.Settings.GetAuthorizedKeys()
	var data []string
	for i := range pkdata {
		data = append(data, hex.EncodeToString(pkdata[i].Marshal()))
	}

	clientdata := &ReverseClientData{Version: rc.version, Hostname: rc.Settings.Hostname(), Username: rc.Settings.User(), PublicKeysHex: data}
	b, _, err := conn.SendRequest("reverse-client", true, ssh.Marshal(clientdata))
	if err != nil {
		log.Printf("ERROR: %+v", err)
	}
	if b == false {
		log.Printf("reverse request rejected")
		return errors.New("reverse request rejected")
	}
	revchan := conn.HandleChannelOpen("reverse")
	sshd := &Server{}
	sshd.Settings = rc.Settings
	sshd.AllowReverse = false
	sshd.ServeChan(revchan)
	return nil
}

// VersionString returns a proper ssh server string as per RFC 4253 Section 4.2
func (rc *ReverseClient) VersionString() string {
	if rc.version == "" {
		rc.version = VERSION
	}
	if strings.HasPrefix(rc.version, RFC425342) {
		return rc.version
	}
	return RFC425342 + rc.version
}

func (rc *ReverseClient) config() *ssh.ClientConfig {
	config := &ssh.ClientConfig{
		ClientVersion: rc.VersionString(),
		User:          rc.Settings.User(),
		Auth:          []ssh.AuthMethod{ssh.PublicKeys(rc.Settings.GetPrivateKeys()...)},
		// HostKeyCallback: khkb,
		HostKeyCallback: rc.hostKeyCallback,
	}
	return config
}

// HostKeyCallback is the function type used for verifying server
// keys. A HostKeyCallback must return nil if the host key is OK, or
// an error to reject it. It receives the hostname as passed to Dial
// or NewClientConn. The remote address is the RemoteAddr of the
// net.Conn underlying the the SSH connection.
func (rc *ReverseClient) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	return rc.Settings.IsKnownHost(hostname, remote, key)
}

func keepAlive(conn *ssh.Client) {
	count := 0
	for {
		if count >= 5 {
			conn.Close()
			return
		}
		time.Sleep(5 * time.Second)
		b, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			log.Printf("Keepalive error %s", err)
			count++
			continue
		}
		if b == false {
			log.Printf("Keepalive error %s", err)
			count++
			continue
		}
		count = 0
	}
}
