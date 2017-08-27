package revssh

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

type channelHandler func(srv *Server, sshConn *ssh.ServerConn, newChan ssh.NewChannel)

func sessionChannelHandler(srv *Server, sshConn *ssh.ServerConn, newChan ssh.NewChannel) {
	channel, reqs, err := newChan.Accept()
	if err != nil {
		log.Printf("could not accept channel (%s)", err)
		// TODO: event callback
		return
	}
	for req := range reqs {
		// log.Printf("session request %s", req.Type)
		switch req.Type {
		case "shell":
			req.Reply(true, nil)
			channel.Write([]byte(fmt.Sprintf("Welcome to %s\n\r", sshConn.User())))
		default:
			newChan.Reject(ssh.UnknownChannelType, fmt.Sprintf("Not Implemented"))
			req.Reply(false, nil)
		}
	}
}
