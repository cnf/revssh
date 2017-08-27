/*
reverseclient binary
*/
package main

import (
	"log"
	"net/http"

	"github.com/cnf/revssh"

	_ "net/http/pprof"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6070", nil))
	}()

	log.SetFlags(log.Lshortfile | log.LstdFlags)

	// settings := NewSettings()
	// settings := revssh.NewFileClientSettings()
	rclient := revssh.NewReverseClient()
	rclient.Settings = revssh.NewFileClientSettings()

	if err := rclient.Connect(); err != nil {
		log.Printf("ERROR: %+v", err)
	}

}
