package revssh

import (
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHChannelConn wraps an ssh.Channel to make it compatible with a net.Conn interface.
type SSHChannelConn struct {
	ssh.Channel
}

// NewSSHChannelConn returns a new SSHChannelConn instanced from an ssh.Channel.
func NewSSHChannelConn(schan ssh.Channel) *SSHChannelConn {
	return &SSHChannelConn{schan}
}

// LocalAddr always returns 'reverse-channel', as this is an ssh.Channel wrapper.
func (cc *SSHChannelConn) LocalAddr() net.Addr {
	return &net.UnixAddr{Name: "reverse-channel", Net: "ssh"}
	// return &net.TCPAddr{IP: net.ParseIP("::1"), Port: 22}
}

// RemoteAddr always returns 'reverse-channel', as this is an ssh.Channel wrapper.
func (cc *SSHChannelConn) RemoteAddr() net.Addr {
	return &net.UnixAddr{Name: "reverse-channel", Net: "ssh"}
	// return &net.TCPAddr{IP: net.ParseIP("::1"), Port: 22}
}

// SetDeadline does nothing, as this is an ssh.Channel wrapper.
func (cc *SSHChannelConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline wrapper, as this is an ssh.Channel wrapper.
func (cc *SSHChannelConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline wrappes, as this is an ssh.Channel wrapper.
func (cc *SSHChannelConn) SetWriteDeadline(t time.Time) error {
	return nil
}
