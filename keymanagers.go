package revssh

import (
	"net"

	"golang.org/x/crypto/ssh"
)

// // IsKnownHost , like a ssh.HostKeyCallback, must return nil if the host key is OK,
// // or an error to reject it. If no entry is found, it will add it.
// type IsKnownHost func(hostname string, remote net.Addr, key ssh.PublicKey) error

// // GetAuthorizedKeys returns all public keys that are authorized to connect to this server.
// type GetAuthorizedKeys func() []ssh.PublicKey

// // GetPrivateKeys returns a list of signers.
// // If no private keys are available, one should be created.
// type GetPrivateKeys func() []ssh.Signer

// A KeyManager handles all public key related functionality.
type KeyManager interface {
	// GetPublicKeys returns all publickeys for a specific username.
	GetPublicKeys(username string) ([]ssh.PublicKey, error)
	// GetAuthorizedKeys returns all public keys that are authorized to connect to this server.
	GetAuthorizedKeys() []ssh.PublicKey
	// AddKnownHost registers a hostname to a specific public key.
	// AddKnownHost(hostname string, pubKey ssh.PublicKey) error
	// GetKnownHost returns the pub key that registered this hostname, if any.
	// GetKnownHost(hostname string) (ssh.PublicKey, error)
	// IsKnownHost , like a ssh.HostKeyCallback, must return nil if the host key is OK,
	// or an error to reject it. If no entry is found, it will add it.
	IsKnownHost(hostname string, remote net.Addr, key ssh.PublicKey) error
	// GetPrivateKeys returns a list of signers.
	// If no private keys are available, one should be created.
	GetPrivateKeys() []ssh.Signer
}

// // A PrivateKeyManager handles private keys.
// type PrivateKeyManager interface {
// 	// GetPrivateKeys returns a list of signers.
// 	// If no private keys are available, one should be created.
// 	GetPrivateKeys() []ssh.Signer
// }
