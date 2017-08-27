/*
Package revssh is the backend code for the reverseclient and server packages.

A reverseclient connects to a revssh server, registers itself as a reverse
client, and acceps sshd connections on incoming reverse ssh channels.

Any ssh client can then connect to the revssh server, and request a JumpProxy
with the hostname registered by a reverseclient, and connect through it.

Binaries are build from "cmd/server/" and "cmd/reverseclient/"
*/
package revssh
