package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

const (
	SERVER_HOST = "192.168.1.42"
	SERVER_PORT = "9988"
	SERVER_TYPE = "tcp"
)

func main() {
	fmt.Println("Server Running....")
	server, err := net.Listen(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)
	if err != nil {
		fmt.Println("Error Listening: ", err.Error())
		os.Exit(1)
	}
	defer server.Close()
	fmt.Println("Listening on " + SERVER_HOST + ":" + SERVER_PORT)
	fmt.Println("Waiting for Client...")
	for {
		connection, err := server.Accept()
		if err != nil {
			fmt.Println("Error Accepting: ", err.Error())
			os.Exit(1)
		}
		fmt.Println(connection)
		fmt.Println("Client Connected")
		// go processClient(connection)
	}
}

func processClient(connection net.Conn) {
	buffer := make([]byte, 1024)
	mLen, err := connection.Read(buffer)
	if err != nil {
		fmt.Println("Error Reading: ", err.Error())
	}
	fmt.Println("Received: ", string(buffer[:mLen]))

	fmt.Print("Enter message to send: ")
	reader := bufio.NewReader(os.Stdin)
	message, _ := reader.ReadString('\n')

	_, err = connection.Write([]byte(message))
	defer connection.Close()
}
