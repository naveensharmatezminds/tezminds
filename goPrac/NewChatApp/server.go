package main

import (
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
	SERVER_HOST = "192.168.1.42"
	SERVER_PORT = "9988"
	SERVER_TYPE = "tcp"
)

var users []string

type UserInfo struct {
	Password  string
	IsActive  bool
	Lastseen  string
	IpAddress string
}

type Chats struct {
	Chat    []string
	NewChat []string
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		if err == io.EOF {
			// fmt.Println("Client disconnected", conn.RemoteAddr())
		} else {
			fmt.Println("Error reading from client:", err)
		}
		return
	}

	userInfo := strings.TrimSpace(string(buffer[:n]))

	if strings.HasPrefix(userInfo, "/contactlist:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			MyContactList(result, conn)
		} else {
			fmt.Println("Invalid input format")
		}
	} else if strings.HasPrefix(userInfo, "/userstatus:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			getUserStatus(result, conn)
		} else {
			fmt.Println("Invalid input format")
		}
	} else if strings.HasPrefix(userInfo, "/getport:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			GetPort(result, conn)
		} else {
			fmt.Println("Invalid input format")
		}
	} else if strings.HasPrefix(userInfo, "/connectwithuser:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			ans := strings.SplitN(result, "#", 2)
			receiverUserName := strings.TrimSpace(ans[0])
			senderUserName := strings.TrimSpace(ans[1])
			ConnectWithUser(receiverUserName, senderUserName, conn)
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
	} else if strings.HasPrefix(userInfo, "/newchat:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			fmt.Println(result)
			manageNewChat(result)

		} else {
			fmt.Println("Invalid input format")
		}
	} else if strings.HasPrefix(userInfo, "/sendchat:") {
		splitResult := strings.SplitN(userInfo, ":", 2)
		if len(splitResult) == 2 {
			result := strings.TrimSpace(splitResult[1])
			fmt.Println(result)
			manageChat(result)

		} else {
			fmt.Println("Invalid input format")
		}
	} else {
		var temp []string
		_ = json.Unmarshal([]byte(userInfo), &temp)

		var data = make(map[string]UserInfo)

		file, err := os.Open("./userData.json")
		if err != nil {
			fmt.Println("Error opening private chat file:", err)
		}
		defer file.Close()

		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&data); err != nil {
			fmt.Println("Error decoding private chat file:", err)
		}

		_, ok := data[temp[0]]

		var message string

		if temp[2] == "Signup" {
			if ok {
				message = "Username already exist, try to create with another username."
				conn.Write([]byte(message))
			} else {
				hash, _ := HashPassword(temp[1])
				data[temp[0]] = UserInfo{Password: hash, IsActive: false, IpAddress: temp[3]}

				// fmt.Println("Data : ", data)

				file, err := os.Create("./userData.json")
				if err != nil {
					fmt.Println("Could not create or overwrite private chat file:", err)
					return
				}
				defer file.Close()

				encoder := json.NewEncoder(file)
				if err := encoder.Encode(data); err != nil {
					fmt.Println("Error encoding private chat data:", err)
					return
				}

				message = "Account created succesfully!!!!"

				conn.Write([]byte(message))

				users = append(users, temp[0])
			}
		} else if temp[2] == "Login" {
			match := CheckPasswordHash(temp[1], data[temp[0]].Password)
			if ok && match {
				mymap := data[temp[0]]
				mymap.IpAddress = temp[3]
				data[temp[0]] = mymap

				file, err := os.Create("./userData.json")
				if err != nil {
					fmt.Println("Could not create or overwrite private chat file:", err)
					return
				}
				defer file.Close()

				encoder := json.NewEncoder(file)
				if err := encoder.Encode(data); err != nil {
					fmt.Println("Error encoding private chat data:", err)
					return
				}

				message = "Login Successful"
				conn.Write([]byte(message))
				users = append(users, temp[0])
			} else {
				message = "Invalid Credential"
				conn.Write([]byte(message))
			}
		} else if temp[2] == "Loginwithsame" {
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

func MyContactList(username string, conn net.Conn) {
	var data = make(map[string]Chats)

	file, err := os.Open("./chatdata.json")
	if err != nil {
		fmt.Println("Error opening private chat file:", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		fmt.Println("Error decoding private chat file:", err)
	}

	var arr []string

	for name, _ := range data {
		if strings.Contains(name, username) {

			splitResult := strings.SplitN(name, ":", 2)
			if len(splitResult) == 2 {
				name1 := strings.TrimSpace(splitResult[0])
				name2 := strings.TrimSpace(splitResult[1])

				if name1 != username {
					arr = append(arr, name1)
				} else if name2 != username {
					arr = append(arr, name2)
				}

			} else {
				fmt.Println("Invalid input format")
			}
			arr = append(arr)
		}
	}

	t, err := json.Marshal(arr)
	finalOutput := string(t)

	_, err = conn.Write([]byte(finalOutput))
	CheckError(err)

}

func GetPort(username string, conn net.Conn) {
	var data = make(map[string]UserInfo)

	file, err := os.Open("./userData.json")
	if err != nil {
		fmt.Println("Error opening private chat file:", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		fmt.Println("Error decoding private chat file:", err)
	}

	ipaddress := data[username].IpAddress

	splitResult := strings.SplitN(ipaddress, ":", 2)
	if len(splitResult) == 2 {
		result := strings.TrimSpace(splitResult[1])
		result = ":" + result
		conn.Write([]byte(result))
	} else {
		fmt.Println("Invalid input format")
	}
}

func ConnectWithUser(receiverUserName, senderUserName string, conn net.Conn) {
	var data = make(map[string]UserInfo)

	file, err := os.Open("./userData.json")
	if err != nil {
		fmt.Println("Error opening private chat file:", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		fmt.Println("Error decoding private chat file:", err)
	}

	_, ok := data[receiverUserName]

	if ok {
		ipaddress := data[receiverUserName].IpAddress
		conn.Write([]byte(ipaddress))

		// Active status

		var data1 = make(map[string]UserInfo)

		file, err := os.Open("./userData.json")
		if err != nil {
			fmt.Println("Error opening private chat file:", err)
		}
		defer file.Close()

		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&data1); err != nil {
			fmt.Println("Error decoding private chat file:", err)
		}

		mymap1 := data1[senderUserName]

		mymap1.IsActive = true
		mymap1.Lastseen = ""

		data1[senderUserName] = mymap1

		file1, err := os.Create("./userData.json")
		if err != nil {
			fmt.Println("Could not create or overwrite private chat file:", err)
			return
		}
		defer file1.Close()

		encoder := json.NewEncoder(file1)
		if err := encoder.Encode(data1); err != nil {
			fmt.Println("Error encoding private chat data:", err)
			return
		}
	} else {
		conn.Write([]byte("Username not exist!"))
	}

}
func manageNewChat(message string) {
	var data = make(map[string]Chats)

	file, err := os.Open("./chatdata.json")
	if err != nil {
		fmt.Println("Error opening private chat file:", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		fmt.Println("Error decoding private chat file:", err)
	}

	opt1 := users[0] + ":" + users[1]
	opt2 := users[1] + ":" + users[0]

	if len(data) == 0 {
		data[opt1] = Chats{Chat: []string{}, NewChat: []string{}}
	} else {
		_, ok1 := data[opt1]
		_, ok2 := data[opt2]

		if ok1 {
			mydata := data[opt1]
			mydata.NewChat = append(mydata.NewChat, message)
			mydata.Chat = append(mydata.Chat, message)
			data[opt1] = mydata
		} else if ok2 {
			mydata := data[opt2]
			mydata.NewChat = append(mydata.NewChat, message)
			mydata.Chat = append(mydata.Chat, message)
			data[opt2] = mydata
		} else {
			mydata := data[opt1]
			mydata.NewChat = append(mydata.NewChat, message)
			mydata.Chat = append(mydata.Chat, message)
			data[opt1] = mydata
		}
	}
	file1, err := os.Create("./chatdata.json")
	if err != nil {
		fmt.Println("Could not create or overwrite private chat file:", err)
		return
	}
	defer file1.Close()

	encoder := json.NewEncoder(file1)
	if err := encoder.Encode(data); err != nil {
		fmt.Println("Error encoding private chat data:", err)
		return
	}
}

func manageChat(message string) {
	var data = make(map[string]Chats)

	file, err := os.Open("./chatdata.json")
	if err != nil {
		fmt.Println("Error opening private chat file:", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		fmt.Println("Error decoding private chat file:", err)
	}

	opt1 := users[0] + ":" + users[1]
	opt2 := users[1] + ":" + users[0]

	if len(data) == 0 {
		data[opt1] = Chats{Chat: []string{message}, NewChat: []string{}}
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
	file1, err := os.Create("./chatdata.json")
	if err != nil {
		fmt.Println("Could not create or overwrite private chat file:", err)
		return
	}
	defer file1.Close()

	encoder := json.NewEncoder(file1)
	if err := encoder.Encode(data); err != nil {
		fmt.Println("Error encoding private chat data:", err)
		return
	}

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
	var data = make(map[string]UserInfo)

	file, err := os.Open("./userData.json")
	if err != nil {
		fmt.Println("Error opening private chat file:", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		fmt.Println("Error decoding private chat file:", err)
	}

	mymap := data[userName]
	mymap.IsActive = false
	mymap.Lastseen = time.Now().Format(time.RFC3339)
	data[userName] = mymap

	file1, err := os.Create("./userData.json")
	if err != nil {
		fmt.Println("Could not create or overwrite private chat file:", err)
		return
	}
	defer file1.Close()

	encoder := json.NewEncoder(file1)
	if err := encoder.Encode(data); err != nil {
		fmt.Println("Error encoding private chat data:", err)
		return
	}

	var disconnectedUser string
	for _, val := range users {
		if val == userName {
			disconnectedUser = val
			break
		}
	}

	mssg := "/anotherclientdisconnected:" + disconnectedUser
	fmt.Println("Name: ", mssg)
	conn.Write([]byte(mssg))

}

func CheckError(err error) {
	if err != nil {
		fmt.Println("Error is : ", err)
		return
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

}

func getUserStatus(username string, conn net.Conn) {
	var data = make(map[string]UserInfo)

	file, err := os.Open("./userData.json")
	if err != nil {
		fmt.Println("Error opening private chat file:", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		fmt.Println("Error decoding private chat file:", err)
	}

	for _, val := range users {
		if val != username {
			flag := data[val].IsActive
			if flag {
				finalOutput := val + " (online)"
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
						finalOutput := val + " (offline) " + "(lastseen : " + date + " " + time + ")"
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
