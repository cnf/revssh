package main

import (
	"log"
	"net/http"

	"github.com/cnf/revssh"

	_ "net/http/pprof"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	log.SetFlags(log.Lshortfile | log.LstdFlags)

	// settings := NewSettings()
	settings := revssh.NewFileServerSettings()
	sshd := revssh.NewServer()
	sshd.Settings = settings
	sshd.Addr = settings.Listen
	sshd.AllowReverse = true
	if err := sshd.ServeTCP(); err != nil {
		log.Printf("ERROR: %+v", err)
	}
}
