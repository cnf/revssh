package revssh

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cnf/revssh/revutil"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	keynames = []string{"ssh_host_ecdsa_key", "ssh_host_ed25519_key", "ssh_host_rsa_key"}
)

// FileClientSettings ...
type FileClientSettings struct {
	KeyManager
	remote   string
	user     string
	hostname string
	// KeyManager *FileKeyManager
}

// NewFileClientSettings ...
func NewFileClientSettings() *FileClientSettings {
	dpath := getDefaultPath()
	cuser, _ := user.Current()
	name := cuser.Username
	var path = flag.String("path", dpath, "configuration path")
	var remote = flag.String("remote", "127.0.0.1:2222", "address:port to connect")
	var username = flag.String("user", name, "ssh user")
	var hostname = flag.String("hostname", "", "hostname to register as")
	flag.Parse()
	return &FileClientSettings{remote: *remote, user: *username, hostname: *hostname, KeyManager: &FileKeyManager{path: *path}}

}

func (s *FileClientSettings) Remote() string {
	return s.remote
}

func (s *FileClientSettings) User() string {
	return s.user
}

func (s *FileClientSettings) Listen() string {
	return ""
}

func (s *FileClientSettings) Hostname() string {
	if s.hostname == "" {
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			return "revssh"
		}
		s.hostname = hostname
	}
	return s.hostname
}

// FileServerSettings ...
type FileServerSettings struct {
	KeyManager
	Listen string
	// path       string
	// KeyManager *FileKeyManager
}

// NewFileServerSettings ...
func NewFileServerSettings() *FileServerSettings {
	cuser, _ := user.Current()
	dpath := fmt.Sprintf("%s/.config/revssh", cuser.HomeDir)
	cdpath, _ := filepath.Abs(dpath)
	// var path = flag.String("path", cdpath, "configuration path")
	var listen = flag.String("listen", ":22", "address:port to listen on")
	flag.Parse()
	// s.path = *path
	// s.path = cdpath
	// s.Listen = *listen
	return &FileServerSettings{Listen: *listen, KeyManager: &FileKeyManager{path: cdpath}}
}

// FileKeyManager ...
type FileKeyManager struct {
	path string
}

// NewFileKeyManager ...
func NewFileKeyManager(path string) *FileKeyManager {
	return &FileKeyManager{path: path}
}

// GetPublicKeys returns all publickeys for a specific username.
func (km *FileKeyManager) GetPublicKeys(username string) ([]ssh.PublicKey, error) {
	return nil, nil
}

// GetAuthorizedKeys returns all public keys that are authorized to connect to this server.
func (km *FileKeyManager) GetAuthorizedKeys() []ssh.PublicKey {
	// TODO: actually reading authorized_keys
	var keys []ssh.PublicKey

	file, err := os.Open(km.getAuthorizedKeysPath())
	if err != nil {
		log.Printf("ERROR: %+v", err)
		return nil
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// log.Println(scanner.Text())
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(scanner.Text()))
		if err != nil {
			log.Printf("ERROR: %+v", err)
			return nil
		}
		keys = append(keys, key)
	}
	return keys
}

// IsKnownHost , like a ssh.HostKeyCallback, must return nil if the host key is OK,
// or an error to reject it. If no entry is found, it will add it.
func (km *FileKeyManager) IsKnownHost(hostname string, remote net.Addr, key ssh.PublicKey) error {
	khkb, err := knownhosts.New(km.getKnownHostPath())
	if err != nil {
		// if strings.HasSuffix(err.Error(), "no such file or directory") || strings.HasSuffix(err.Error(), "The system cannot find the file specified") {
		if os.IsNotExist(err) {
			return revutil.AppendLine(km.getKnownHostPath(), knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key))
		}
		return err
	}
	err = khkb(hostname, remote, key)
	if err != nil {
		if os.IsNotExist(err) || strings.HasSuffix(err.Error(), "knownhosts: key is unknown") {
			// TODO: do we need to add remote net.Addr as one of the hostnames?
			return revutil.AppendLine(km.getKnownHostPath(), knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key))
		}
		return err
	}
	return nil
}

func (km *FileKeyManager) getKnownHostPath() string {
	// return fmt.Sprintf("%s/known_hosts", km.path)
	return filepath.Join(km.path, "known_hosts")

}

func (km *FileKeyManager) getAuthorizedKeysPath() string {
	return filepath.Join(km.path, "authorized_keys")
}

// GetPrivateKeys returns a list of signers.
// If no private keys are available, one should be created.
func (km *FileKeyManager) GetPrivateKeys() []ssh.Signer {
	path, err := getConfigDir(km.path)
	if err != nil {
		log.Panicf("ERROR: can't get config dir: %s", err)
	}
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Panicf("ERROR: can't get config dir: %s", err)
	}
	sort.Strings(keynames)
	hostKeys := make([]ssh.Signer, 0)
	for fi := range files {
		ki := sort.SearchStrings(keynames, files[fi].Name())
		if ki < len(keynames) && keynames[ki] == files[fi].Name() {
			hostKey, err := revutil.ParsePrivateKeyFile(fmt.Sprintf("%s/%s", path, files[fi].Name()))
			if err != nil {
				log.Printf("%+v", err)
				continue
			}
			hostKeys = append(hostKeys, hostKey)
		}
	}
	return hostKeys
}

func getConfigDir(path string) (string, error) {
	// TODO: validate
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return "", err
	}
	return path, nil
}

func getDefaultPath() string {
	var dpath string
	if runtime.GOOS == "windows" {
		dpath, _ = filepath.Abs("C:/RevSSH")
	} else {
		cuser, _ := user.Current()
		dpath, _ = filepath.Abs(fmt.Sprintf("%s/.config/revssh", cuser.HomeDir))
	}
	return dpath
}
