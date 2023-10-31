package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

var db *sql.DB

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	FullName  string    `json:"fullname"`
	IsActive  bool      `json:"isactive"`
	Lastseen  time.Time `json:"lastseen"`
	CreatedAt string    `json:"created_at"`
	MobileNo  int64     `json:"mobile_no"`
	Bio       string    `json:"bio"`
	Gender    string    `json:"gender"`
	UpdatedAt string    `json:"updated_at"`
}

type ResponseUser struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	FullName  string    `json:"fullname"`
	IsActive  bool      `json:"isactive"`
	Lastseen  time.Time `json:"lastseen"`
	CreatedAt string    `json:"created_at"`
	MobileNo  int64     `json:"mobile_no"`
	Bio       string    `json:"bio"`
	Gender    string    `json:"gender"`
	UpdatedAt string    `json:"updated_at"`
}

type UserResponse struct {
	ErrorCode    int         `json:"errorCode"`
	ErrorMessage string      `json:"errorMessage"`
	Data         interface{} `json:"data"`
}

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error
	db, err = sql.Open("mysql", connectionString)
	if err != nil {
		log.Fatal(err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/users", getAllUsers).Methods("GET")
	r.HandleFunc("/user/{username}", getUser).Methods("GET")
	r.HandleFunc("/user", addUser).Methods("POST")
	r.HandleFunc("/user/{username}", updateUser).Methods("PUT")
	r.HandleFunc("/user/{username}", deleteUser).Methods("DELETE")

	serverTLSCert, err := tls.LoadX509KeyPair("/etc/ssl/certs/apache-selfsigned.crt", "/etc/ssl/private/apache-selfsigned.key")
	if err != nil {
		log.Fatalf("Error loading certificate and key file: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}

	server := http.Server{
		Addr:      ":443",
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	// c := cors.New(cors.Options{
	//  AllowedOrigins: []string{"*"},
	//  AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
	//  AllowedHeaders: []string{"Accept", "Content-Type", "Authorization"},
	// })

	// handler := c.Handler(r)

	fmt.Printf("Server listening on port 443...\n")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	er := db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&username)

	if er == sql.ErrNoRows {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "Username not exist",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: err.Error(),
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return

	}

	if !isValidUsername(user.Username) {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "Username should be minimum of 5 characters and only alphabets should be there",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	if !isValidPassword(user.Password) {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "Required strong password",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	if !isValidMobile(int(user.MobileNo)) {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "Mobile number should be of 10 digits.",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	if !isValidGender(user.Gender) {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "Choose Gender Male, Female or Other only.",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	_, err = db.Exec("UPDATE users SET username=?, password=?, fullname=?, mobile_no=?, bio=?, gender=? WHERE username=?", user.Username, user.Password, user.FullName, user.MobileNo, user.Bio, user.Gender, username)
	if err != nil {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: err.Error(),
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	row1 := db.QueryRow("SELECT * FROM users WHERE username = ?", username)
	var getuser User

	var lastseen []uint8
	// var createdat []uint8
	// var updatedat []uint8

	row1.Scan(
		&getuser.ID, &getuser.Username, &getuser.Password, &getuser.FullName, &getuser.IsActive,
		&lastseen, &getuser.CreatedAt, &getuser.MobileNo, &getuser.Bio, &getuser.Gender, &getuser.UpdatedAt,
	)

	getuser.Lastseen, _ = time.Parse("2006-01-02 15:04:05", string(lastseen))
	// getuser.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", string(createdat))
	// getuser.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", string(updatedat))

	resUser := ResponseUser{
		ID:        getuser.ID,
		Username:  getuser.Username,
		FullName:  getuser.FullName,
		IsActive:  getuser.IsActive,
		Lastseen:  getuser.Lastseen,
		CreatedAt: getuser.CreatedAt,
		MobileNo:  getuser.MobileNo,
		Bio:       getuser.Bio,
		Gender:    getuser.Gender,
		UpdatedAt: getuser.UpdatedAt,
	}

	if err != nil {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: err.Error(),
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := UserResponse{
		ErrorCode:    0,
		ErrorMessage: "",
		Data:         resUser,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	row1 := db.QueryRow("SELECT * FROM users WHERE username = ?", username)
	var getuser User

	var lastseen []uint8
	// var createdat []uint8
	// var updatedat []uint8

	row1.Scan(
		&getuser.ID, &getuser.Username, &getuser.Password, &getuser.FullName, &getuser.IsActive,
		&lastseen, &getuser.CreatedAt, &getuser.MobileNo, &getuser.Bio, &getuser.Gender, &getuser.UpdatedAt,
	)

	getuser.Lastseen, _ = time.Parse("2006-01-02 15:04:05", string(lastseen))
	// getuser.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", string(createdat))
	// getuser.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", string(updatedat))

	resUser := ResponseUser{
		ID:        getuser.ID,
		Username:  getuser.Username,
		FullName:  getuser.FullName,
		IsActive:  getuser.IsActive,
		Lastseen:  getuser.Lastseen,
		CreatedAt: getuser.CreatedAt,
		MobileNo:  getuser.MobileNo,
		Bio:       getuser.Bio,
		Gender:    getuser.Gender,
		UpdatedAt: getuser.UpdatedAt,
	}

	if resUser.ID == 0 {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "No such user found!",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	_, err := db.Exec("DELETE FROM users WHERE username=?", username)
	fmt.Println("Error :", err)
	if err != nil {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: err.Error(),
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := UserResponse{
		ErrorCode:    0,
		ErrorMessage: "",
		Data:         resUser,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Add User

func addUser(w http.ResponseWriter, r *http.Request) {
	var user User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: err.Error(),
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	defer r.Body.Close()

	if !isValidUsername(user.Username) {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "Username should be minimum of 5 characters and only alphabets should be there",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	if !isValidPassword(user.Password) {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "Required strong password",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	if !isValidMobile(int(user.MobileNo)) {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "Mobile number should be of 10 digits.",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	if !isValidGender(user.Gender) {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "Choose Gender Male, Female or Other only.",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	user.Lastseen = time.Now()
	// user.CreatedAt = time.Now()
	// user.UpdatedAt = time.Now()

	_, err := db.Exec("INSERT INTO users ( username, password, fullname, isactive, lastseen, mobile_no, bio, gender) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?)",
		user.Username, user.Password, user.FullName, user.IsActive, user.Lastseen, user.MobileNo, user.Bio, user.Gender)
	if err != nil {
		if strings.Contains(err.Error(), "Error 1062") {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: "Username already exist, try with other username.",
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			fmt.Println(err)
			return
		} else {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: err.Error(),
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			fmt.Println(err)
			return
		}
	}

	row1 := db.QueryRow("SELECT * FROM users WHERE username = ?", user.Username)
	var getuser User

	var lastseen []uint8
	// var createdat []uint8
	// var updatedat []uint8

	row1.Scan(
		&getuser.ID, &getuser.Username, &getuser.Password, &getuser.FullName, &getuser.IsActive,
		&lastseen, &getuser.CreatedAt, &getuser.MobileNo, &getuser.Bio, &getuser.Gender, &getuser.UpdatedAt,
	)

	getuser.Lastseen, _ = time.Parse("2006-01-02 15:04:05", string(lastseen))
	// getuser.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", string(createdat))
	// getuser.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", string(updatedat))

	resUser := ResponseUser{
		ID:        getuser.ID,
		Username:  getuser.Username,
		FullName:  getuser.FullName,
		IsActive:  getuser.IsActive,
		Lastseen:  getuser.Lastseen,
		CreatedAt: getuser.CreatedAt,
		MobileNo:  getuser.MobileNo,
		Bio:       getuser.Bio,
		Gender:    getuser.Gender,
		UpdatedAt: getuser.UpdatedAt,
	}

	if err != nil {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: err.Error(),
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := UserResponse{
		ErrorCode:    0,
		ErrorMessage: "",
		Data:         resUser,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetAll

func getAllUsers(w http.ResponseWriter, r *http.Request) {

	isQuery := r.URL.Query()
	if len(isQuery) == 0 {
		rows, err := db.Query("SELECT * FROM users ")
		if err != nil {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: err.Error(),
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		}
		defer rows.Close()

		var users []ResponseUser
		for rows.Next() {
			var user User

			var lastseen []uint8
			// var createdat []uint8
			// var updatedat []uint8
			err := rows.Scan(
				&user.ID, &user.Username, &user.Password, &user.FullName, &user.IsActive,
				&lastseen, &user.CreatedAt, &user.MobileNo, &user.Bio, &user.Gender, &user.UpdatedAt,
			)

			user.Lastseen, _ = time.Parse("2006-01-02 15:04:05", string(lastseen))
			// user.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", string(createdat))
			// user.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", string(updatedat))

			resUser := ResponseUser{
				ID:        user.ID,
				Username:  user.Username,
				FullName:  user.FullName,
				IsActive:  user.IsActive,
				Lastseen:  user.Lastseen,
				CreatedAt: user.CreatedAt,
				MobileNo:  user.MobileNo,
				Bio:       user.Bio,
				Gender:    user.Gender,
				UpdatedAt: user.UpdatedAt,
			}

			if err != nil {
				response := UserResponse{
					ErrorCode:    1,
					ErrorMessage: err.Error(),
					Data:         nil,
				}
				json.NewEncoder(w).Encode(response)
				return
			}
			users = append(users, resUser)

		}
		if len(users) == 0 {
			response := UserResponse{
				ErrorCode:    0,
				ErrorMessage: "Database is Empty!",
				Data:         users,
			}
			json.NewEncoder(w).Encode(response)
			return
		}
		response := UserResponse{
			ErrorCode:    0,
			ErrorMessage: "",
			Data:         users,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		searchQuery := r.URL.Query().Get("search")
		start := r.URL.Query().Get("start") // Current page number
		limit := r.URL.Query().Get("limit") // Number of items per page

		if start == "" {
			start = "1"
		}
		if limit == "" {
			limit = "10"
		}

		startInt, err := strconv.Atoi(start)
		if err != nil {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: err.Error(),
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		limitInt, err := strconv.Atoi(limit)
		if err != nil {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: err.Error(),
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		query := "SELECT id, username, fullname, isactive, mobile_no, bio, gender FROM users WHERE " +
			"username LIKE ? OR fullname LIKE ? OR isactive LIKE ? OR mobile_no LIKE ? OR bio LIKE ? OR gender LIKE ? " +
			"LIMIT ? OFFSET ?"

		rows, err := db.Query(query, "%"+searchQuery+"%", "%"+searchQuery+"%", "%"+searchQuery+"%", "%"+searchQuery+"%", "%"+searchQuery+"%", "%"+searchQuery+"%", limitInt, startInt-1)

		if err != nil {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: err.Error(),
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		}
		defer rows.Close()

		var users []ResponseUser
		for rows.Next() {
			var user ResponseUser
			err := rows.Scan(&user.ID, &user.Username, &user.FullName, &user.IsActive, &user.MobileNo, &user.Bio, &user.Gender)
			if err != nil {
				response := UserResponse{
					ErrorCode:    1,
					ErrorMessage: err.Error(),
					Data:         nil,
				}
				json.NewEncoder(w).Encode(response)
				return
			}
			users = append(users, user)
		}
		response := UserResponse{
			ErrorCode:    0,
			ErrorMessage: "",
			Data:         users,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}

}

// Get

func getUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	row := db.QueryRow("SELECT * FROM users WHERE username = ?", username)
	var user User

	var lastseen []uint8
	// var createdat []uint8
	// var updatedat []uint8

	err := row.Scan(
		&user.ID, &user.Username, &user.Password, &user.FullName, &user.IsActive,
		&lastseen, &user.CreatedAt, &user.MobileNo, &user.Bio, &user.Gender, &user.UpdatedAt,
	)
	if err != nil {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: "No such user found!",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	user.Lastseen, _ = time.Parse("2006-01-02 15:04:05", string(lastseen))
	// user.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", string(createdat))
	// user.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", string(updatedat))

	resUser := ResponseUser{
		ID:        user.ID,
		Username:  user.Username,
		FullName:  user.FullName,
		IsActive:  user.IsActive,
		Lastseen:  user.Lastseen,
		CreatedAt: user.CreatedAt,
		MobileNo:  user.MobileNo,
		Bio:       user.Bio,
		Gender:    user.Gender,
		UpdatedAt: user.UpdatedAt,
	}

	if err != nil {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: err.Error(),
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := UserResponse{
		ErrorCode:    0,
		ErrorMessage: "",
		Data:         resUser,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func isValidMobile(mobile_no int) bool {
	s := strconv.Itoa(mobile_no)
	if len(s) == 10 {
		return true
	}
	return false
}

func isValidUsername(username string) bool {
	if len(username) < 5 {
		return false
	}
	for _, r := range username {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func isValidPassword(password string) bool {
	secure := true
	tests := []string{".{8,15}", "[a-z]", "[A-Z]", "[0-9]", "[^\\d\\w]"}
	for _, test := range tests {
		t, err := regexp.MatchString(test, password)
		if err != nil {
			fmt.Printf("Regex error: %v\n", err)
			return false
		}

		if !t {
			secure = false
			break
		}
	}
	return secure
}

func isValidGender(gender string) bool {
	secure := false
	if gender == "Male" || gender == "Female" || gender == "Other" {
		secure = true
	}
	return secure
}
