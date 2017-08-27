package revssh

import (
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

// direct-tcpip data struct as specified in RFC4254, Section 7.2
type forwardData struct {
	DestinationHost string
	DestinationPort uint32

	OriginatorHost string
	OriginatorPort uint32
}

func directTcpipChannelHandler(srv *Server, sshConn *ssh.ServerConn, newChan ssh.NewChannel) {
	log.Printf("direct tcp-ip handler")
	d := forwardData{}
	var conn net.Conn
	if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(ssh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}
	// TODO: callback to allow / deny specific forwarding
	rc, err := srv.ReverseClientList.GetReverseClient(d.DestinationHost, sshConn.User())
	if err != nil || rc == nil {
		dest := fmt.Sprintf("%s:%d", d.DestinationHost, d.DestinationPort)
		var dialer net.Dialer
		conn, err = dialer.Dial("tcp", dest)
		if err != nil {
			newChan.Reject(ssh.ConnectionFailed, err.Error())
			log.Printf("%s", err.Error())
			return
		}
	} else {
		rchannel, rreqs, err := rc.SSHConn.OpenChannel("reverse", newChan.ExtraData())
		if err != nil {
			newChan.Reject(ssh.ConnectionFailed, "Could not open forward channel")
			log.Printf("Reverse Channel error: %+v", err)
			return
		}
		go ssh.DiscardRequests(rreqs)
		conn = NewSSHChannelConn(rchannel)
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		conn.Close()
		log.Printf("Error: %+v", conn)

		return
	}
	go ssh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer conn.Close()
		io.Copy(ch, conn)
	}()
	go func() {
		defer ch.Close()
		defer conn.Close()
		io.Copy(conn, ch)

	}()
	log.Println("Got a reverse SSH channel")

	// dest := fmt.Sprintf("%s:%d", d.DestinationHost, d.DestinationPort)
	// log.Printf("direct-tcp-ip %+v", d)
}
