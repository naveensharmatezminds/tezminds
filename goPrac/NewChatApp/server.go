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

	"golang.org/x/crypto/bcrypt"
)

const (
	SERVER_HOST = "192.168.1.19"
	SERVER_PORT = "9988"
	SERVER_TYPE = "tcp"
)

var users = []string{"asdf", "asdfg"}

type UserInfo struct {
	Password string
	IsLogin  bool
	Lastseen string
}

type Chats struct {
	Chat []string
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		if err == io.EOF {
			fmt.Println("Client disconnected:", conn.RemoteAddr())
		} else {
			fmt.Println("Error reading from client:", err)
		}
		return
	}

	userInfo := strings.TrimSpace(string(buffer[:n]))

	fmt.Println("UserInfo: ", userInfo)

	if strings.HasPrefix(userInfo, "/userstatus:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			getUserStatus(result, conn)
		} else {
			fmt.Println("Invalid input format")
		}
	} else if strings.HasPrefix(userInfo, "/previouschat:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			ans := strings.SplitN(result, "#", 2)
			userName := strings.TrimSpace(ans[0])
			passWord := strings.TrimSpace(ans[1])
			prevMessages(userName, passWord, conn)
		} else {
			fmt.Println("Invalid input format")
		}
	} else if strings.HasPrefix(userInfo, "/close:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			updateIsLoggedIn(result, conn)

		} else {
			fmt.Println("Invalid input format")
		}
	} else if strings.HasPrefix(userInfo, "/sendchat:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			manageChat(result)

		} else {
			fmt.Println("Invalid input format")
		}
	} else {
		var temp []string
		_ = json.Unmarshal([]byte(userInfo), &temp)

		file, err := os.Open("./userData.json")
		CheckError(err)
		defer file.Close()

		scan := bufio.NewScanner(file)
		scan.Scan()
		line := scan.Text()

		var data = make(map[string]UserInfo)

		_ = json.Unmarshal([]byte(line), &data)

		_, ok := data[temp[0]]

		var message string

		if temp[2] == "Signup" {
			if ok {
				message = "Username already exist, try to create with another username."
				conn.Write([]byte(message))
			} else {
				hash, _ := HashPassword(temp[1])
				data[temp[0]] = UserInfo{Password: hash, IsLogin: true}

				t, err := json.Marshal(data)
				CheckError(err)

				finalOut := string(t)

				myfile, err := os.OpenFile("./userData.json", os.O_CREATE|os.O_WRONLY, 0644)
				CheckError(err)

				_, err = io.WriteString(myfile, finalOut)
				CheckError(err)

				message = "Account created succesfully!!!!"

				conn.Write([]byte(message))

				users = append(users, temp[0])
			}
		} else {
			match := CheckPasswordHash(temp[1], data[temp[0]].Password)
			if ok && match {
				message = "Login Successful"
				conn.Write([]byte(message))
				users = append(users, temp[0])
			} else {
				message = "Invalid Credential"
				conn.Write([]byte(message))
			}
		}
	}

}

func manageChat(message string) {
	file, err := os.Open("./chatdata.json")
	CheckError(err)
	defer file.Close()

	scan := bufio.NewScanner(file)
	scan.Scan()
	line := scan.Text()

	var data = make(map[string]Chats)

	_ = json.Unmarshal([]byte(line), &data)

	opt1 := users[0] + ":" + users[1]
	opt2 := users[1] + ":" + users[0]

	if len(data) == 0 {
		data[opt1] = Chats{Chat: []string{message}}
	} else {
		_, ok1 := data[opt1]
		_, ok2 := data[opt2]

		if ok1 {
			mydata := data[opt1]
			mydata.Chat = append(mydata.Chat, message)
			data[opt1] = mydata
		} else if ok2 {
			mydata := data[opt2]
			mydata.Chat = append(mydata.Chat, message)
			data[opt2] = mydata
		} else {
			mydata := data[opt1]
			mydata.Chat = append(mydata.Chat, message)
			data[opt1] = mydata
		}
	}
	t, err := json.Marshal(data)
	CheckError(err)

	finalOut := string(t)

	myfile, err := os.OpenFile("./chatdata.json", os.O_CREATE|os.O_WRONLY, 0644)
	CheckError(err)

	_, err = io.WriteString(myfile, finalOut)
	CheckError(err)

	myfile.Close()

}

func main() {
	listener, err := net.Listen(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)
	CheckError(err)
	defer listener.Close()

	fmt.Println("Server started. Waiting for clients...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		fmt.Println()
		go handleConnection(conn)
	}
}

func updateIsLoggedIn(userName string, conn net.Conn) {
	file, err := os.Open("./userData.json")
	CheckError(err)
	defer file.Close()

	scan := bufio.NewScanner(file)
	scan.Scan()
	line := scan.Text()

	var data = make(map[string]UserInfo)

	_ = json.Unmarshal([]byte(line), &data)

	mymap := data[userName]
	mymap.IsLogin = false
	mymap.Lastseen = time.Now().Format(time.RFC3339)
	data[userName] = mymap

	t, err := json.Marshal(data)
	CheckError(err)

	finalOut := string(t)

	myfile, err := os.OpenFile("./userData.json", os.O_CREATE|os.O_WRONLY, 0644)
	CheckError(err)

	_, err = io.WriteString(myfile, finalOut)
	CheckError(err)

	var disconnectedUser string
	for _, val := range users {
		if val == userName {
			disconnectedUser = val
		}
	}

	mssg := "/anotherclientdisconnected:" + disconnectedUser
	fmt.Println("Name: ", mssg)
	conn.Write([]byte(mssg))

	myfile.Close()

}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

func prevMessages(username string, password string, conn net.Conn) {
	file, err := os.Open("./chatdata.json")

	CheckError(err)
	defer file.Close()

	decoder := json.NewDecoder(file)
	var data = make(map[string]Chats)
	if err := decoder.Decode(&data); err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	CheckError(err)
	defer file.Close()

	opt1 := users[0] + ":" + users[1]
	opt2 := users[1] + ":" + users[0]
	fmt.Println("Username: ", username, " Password: ", password)
	_, ok1 := data[opt1]
	_, ok2 := data[opt2]

	var arr []string

	if ok1 {
		for _, val := range data[opt1].Chat {
			arr = append(arr, val)
		}
	} else if ok2 {
		for _, val := range data[opt2].Chat {
			arr = append(arr, val)
		}
	}

	t, err := json.Marshal(arr)
	finalOutput := string(t)

	finalOutput = "/allchat:" + finalOutput

	_, err = conn.Write([]byte(finalOutput))
	CheckError(err)

	// Active status

	myfile, err := os.Open("./userData.json")
	CheckError(err)
	defer file.Close()

	scan := bufio.NewScanner(myfile)
	scan.Scan()
	line := scan.Text()

	var data1 = make(map[string]UserInfo)

	_ = json.Unmarshal([]byte(line), &data1)

	var mymap1 = make(map[string]UserInfo)
	mymap1 = data1

	mymap1[username] = UserInfo{Password: data1[username].Password, IsLogin: true, Lastseen: ""}

	t1, err := json.Marshal(mymap1)
	CheckError(err)

	finalOut := string(t1)

	myfile1, err := os.OpenFile("./userData.json", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	CheckError(err)
	_, err = io.WriteString(myfile1, "")

	_, err = io.WriteString(myfile1, finalOut)
	CheckError(err)

}

func getUserStatus(username string, conn net.Conn) {
	file, err := os.Open("./userData.json")
	CheckError(err)
	defer file.Close()

	scan := bufio.NewScanner(file)
	scan.Scan()
	line := scan.Text()

	var data = make(map[string]UserInfo)

	_ = json.Unmarshal([]byte(line), &data)

	for _, val := range users {
		if val != username {
			flag := data[val].IsLogin
			if flag {
				finalOutput := val + " is online"
				_, err = conn.Write([]byte(finalOutput))
				CheckError(err)
			} else {
				if len(data[val].Lastseen) > 0 {
					splitResult := strings.SplitN(data[val].Lastseen, "T", 2)
					if len(splitResult) == 2 {
						date := strings.TrimSpace(splitResult[0])
						timezone := strings.TrimSpace(splitResult[1])
						split := strings.SplitN(timezone, "+", 2)
						time := strings.TrimSpace(split[0])
						finalOutput := val + " is offline " + "(Lastseen : " + date + " " + time + ")"
						_, err = conn.Write([]byte(finalOutput))
						CheckError(err)

					} else {
						fmt.Println("Invalid input format")
					}
				}

			}
		}
	}
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
