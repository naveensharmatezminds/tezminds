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
	fmt.Println("Client Running...")
	connection, err := net.Dial(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)
	if err != nil {
		fmt.Println("Error connecting to server:", err.Error())
		os.Exit(1)
	}
	defer connection.Close()

	fmt.Print("Enter message to send: ")
	reader := bufio.NewReader(os.Stdin)
	message, _ := reader.ReadString('\n')

	_, err = connection.Write([]byte(message))
	if err != nil {
		fmt.Println("Error reading: ", err.Error())
		os.Exit(1)
	}

	buffer := make([]byte, 1024)
	mLen, err := connection.Read(buffer)
	if err != nil {
		fmt.Println("Error reading: ", err.Error())
		os.Exit(1)
	}
	fmt.Println(string(buffer[:mLen]))
}
