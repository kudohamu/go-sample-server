package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	service := ":51456"
	tcpAddr, err := net.ResolveTCPAddr("tcp", service)
	checkError(err)
	listner, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)
	for {
		conn, err := listner.Accept()
		if err != nil {
			continue
		}
		fmt.Println("client accept!")
		messageBuf := make([]byte, 1024)
		messageLen, err := conn.Read(messageBuf)
		checkError(err)

		message := string(messageBuf[:messageLen])
		message = message + " too!"

		conn.Write([]byte(message))
	}
	os.Exit(0)
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: error: %s", err.Error())
		os.Exit(1)
	}
}
