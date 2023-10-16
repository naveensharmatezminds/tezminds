package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const (
	SERVER_HOST = "192.168.1.19"
	SERVER_PORT = "9988"
	SERVER_TYPE = "tcp"
)

var file, _ = os.OpenFile("./mylogfile.txt", os.O_CREATE|os.O_WRONLY, 0644)

var senderIP string = "192.168.1.42"
var receiverIp string

type User struct {
	IpAddress string
	UserInfo  UserInfo
}

type UserInfo struct {
	Username string
	Chat     []string
}


func main() {
	connection, err := net.Dial(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)
	if err != nil {
		fmt.Println("Error connecting to server:", err.Error())
		os.Exit(1)
	}
	defer connection.Close()

	if err != nil {
		panic(err)
	}

	// Storage()

	clientAddr := connection.RemoteAddr().String()

	go func() { serverStart(clientAddr, connection) }()
	fmt.Print("\nHost to connect to: ")
	var host string
	fmt.Scanln(&host)

	ip, _, err := net.SplitHostPort(host)
	if err != nil {
		fmt.Println("Invalid input format. Please provide IP address and port.")
		return
	}

	receiverIp = ip

	prevMessages()

	for {

		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		mymsg := scanner.Text()

		currentTime := time.Now()

		timeString := currentTime.Format("2006-01-02 15:04:05")

		text := "Naveen Sharma : " + timeString + " " + mymsg

		username := strings.Split(text, ":")[0]

		file, err := os.Open("./mylogfile.txt")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		scan := bufio.NewScanner(file)
		scan.Scan()
		line := scan.Text()

		if err := scan.Err(); err != nil {
			fmt.Println(err)
			return
		}

		var arr []User
		_ = json.Unmarshal([]byte(line), &arr)

		if len(arr) == 0 {
			arr = append(arr, User{IpAddress: receiverIp, UserInfo: UserInfo{Username: username, Chat: []string{text}}})
		} else {
			var isUserFound bool = false
			for i := 0; i < len(arr); i++ {
				if arr[i].IpAddress == receiverIp {
					arr[i].UserInfo.Chat = append(arr[i].UserInfo.Chat, text)
					isUserFound = true
				}
			}
			if isUserFound == false {
				arr = append(arr, User{IpAddress: receiverIp, UserInfo: UserInfo{Username: username, Chat: []string{text}}})
			}
		}

		// _, err := io.WriteString(file, text)
		users = arr

		t, err := json.Marshal(users)
		if err != nil {
			panic(err)
		}

		finalOut := string(t)

		myfile, err := os.OpenFile("./mylogfile.txt", os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = io.WriteString(myfile, finalOut)
		if err != nil {
			fmt.Println(err)
			return
		}

		myfile.Close()

		if err != nil {
			panic(err)
		}

		SendMessage(timeString+" "+scanner.Text()+"\n", host)

	}
}

func prevMessages() {

	file, err := os.Open("./mylogfile.txt")

	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan()
	line := scanner.Text()

	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		return
	}

	var arr []User
	_ = json.Unmarshal([]byte(line), &arr)
	// log.Printf("Unmarshaled: %v", arr)
	// fmt.Println(arr[0])

	var userChatArr []string
	// using for loop
	for i := 0; i < len(arr); i++ {

		if arr[i].IpAddress == receiverIp {
			userChatArr = arr[i].UserInfo.Chat
			break

		}

	}
	for _, val := range userChatArr {
		fmt.Println(val)
	}
}
func serverStart(clientAddr string, connection net.Conn) {

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

		go HandleNewMsg(c, connection)

	}
}

func HandleNewMsg(c net.Conn, connection net.Conn) {

	clientAddr := c.RemoteAddr().String()

	receiverIp = strings.Split(clientAddr, ":")[0]

	for {
		netData, err := bufio.NewReader(c).ReadString('\n')

		if err != nil {
			fmt.Println(err)
			return
		}

		msg := strings.TrimSpace(string(netData)) //naveen : hey
		fmt.Println(msg)

		username := strings.Split(msg, ":")[0]

		file, err := os.Open("./mylogfile.txt")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scanner.Scan()
		line := scanner.Text()

		if err := scanner.Err(); err != nil {
			fmt.Println(err)
			return
		}

		var arr []User
		_ = json.Unmarshal([]byte(line), &arr)

		if len(arr) == 0 {
			arr = append(arr, User{IpAddress: receiverIp, UserInfo: UserInfo{Username: username, Chat: []string{msg}}})
		} else {
			var isUserFound bool = false
			for i := 0; i < len(arr); i++ {
				if arr[i].IpAddress == receiverIp {
					arr[i].UserInfo.Chat = append(arr[i].UserInfo.Chat, msg)
					isUserFound = true
				}
			}
			if isUserFound == false {
				arr = append(arr, User{IpAddress: receiverIp, UserInfo: UserInfo{Username: username, Chat: []string{msg}}})
			}
		}

		users = arr

		text, err := json.Marshal(users)
		if err != nil {
			panic(err)
		}

		finalOut := string(text)

		myfile, err := os.OpenFile("./mylogfile.txt", os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = io.WriteString(myfile, finalOut)
		if err != nil {
			fmt.Println(err)
			return
		}

		myfile.Close()

		if err != nil {
			panic(err)
		}

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

	c.Write([]byte("Naveen Sharma :" + " " + message + "\n"))
	bufio.NewReader(c).ReadString('\n')

}


users := make(map[string]UserInfo)

// more optimized code
// {
// 	192.168.1.19" :  {
// 								   "Username": "Naveen Sharma ",
// 								   "Chat": [
// 								  "Naveen Sharma : 2023-10-10 18:38:25 hello",
// 								   "Kaushal : 2023-10-10 18:38:34 hii",
// 									"Naveen Sharma : 2023-10-10 18:39:01 Done with this app"
// 													]
// 									}
// 	}

// 	objname[192.168.1.19].chat
