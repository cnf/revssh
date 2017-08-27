buildserver:
	gox -os="windows linux darwin" -arch="amd64" -output="bin/reversessh_{{.OS}}_{{.Arch}}" github.com/cnf/revssh/cmd/server

server: buildserver
	./bin/reversessh_darwin_amd64 -listen 127.0.0.1:2222

buildclient:
	gox -os="windows linux darwin" -arch="amd64" -output="bin/reverseclient_{{.OS}}_{{.Arch}}" github.com/cnf/revssh/cmd/reverseclient

client: buildclient
	./bin/reverseclient_darwin_amd64 -user cnf -remote 127.0.0.1:2222

clean:
	rm -f bin/reverseclient_* bin/reversessh_*
