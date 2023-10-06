package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	SERVER_HOST = "192.168.1.19"
	SERVER_PORT = "9988"
	SERVER_TYPE = "tcp"
)

func main() {
	connection, err := net.(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)
	if err != nil {
		fmt.Println("Error connecting to server:", err.Error())
		os.Exit(1)
	}
	defer connection.Close()
	go func() { serverStart() }()
	fmt.Print("\nHost to connect to: ")
	var host string
	fmt.Scanln(&host)
	for {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		SendMessage(scanner.Text(), host)
	}
}

func serverStart() {
	PORT := ":" + os.Args[1]
	l, err := net.Listen("tcp", PORT)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go HandleNewMsg(c)
	}
}

func HandleNewMsg(c net.Conn) {
	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}
		msg := strings.TrimSpace(string(netData))
		println("New Msg: " + msg)
		c.Close()
		break
	}
}

func SendMessage(message, host string) {
	CONNECT := host
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		fmt.Println(err)
		return
	}

	c.Write([]byte(message + "\n"))
	bufio.NewReader(c).ReadString('\n')

}
