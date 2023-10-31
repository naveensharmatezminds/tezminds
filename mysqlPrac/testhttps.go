package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

var (
	CertFilePath = "/etc/ssl/certs/apache-selfsigned.crt"
	KeyFilePath  = "/etc/ssl/private/apache-selfsigned.key"
)

func httpRequestHandler(w http.ResponseWriter, req *http.Request) {
	// w.Write([]byte("Hello, World!\n"))
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Get database credentials from environment variables
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error
	db, err = sql.Open("mysql", connectionString)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	r := mux.NewRouter()

	isQuery := r.URL.Query()
	if len(isQuery) == 0 {
		rows, err := db.Query("SELECT * FROM users ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// searchUsers()

		var users []ResponseUser
		for rows.Next() {
			var user User

			var lastseen []uint8
			var createdat []uint8
			var updatedat []uint8
			err := rows.Scan(
				&user.ID, &user.Username, &user.Password, &user.FullName, &user.IsActive,
				&lastseen, &createdat, &user.MobileNo, &user.Bio, &user.Gender, &updatedat,
			)

			user.Lastseen, _ = time.Parse("2006-01-02 15:04:05", string(lastseen))
			user.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", string(createdat))
			user.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", string(updatedat))

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
					ErrorMessage: "Unable to get users",
					Data:         nil,
				}
				json.NewEncoder(w).Encode(response)
				return
			}
			users = append(users, resUser)

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
			http.Error(w, "Invalid start number", http.StatusBadRequest)
			return
		}

		limitInt, err := strconv.Atoi(limit)
		if err != nil {
			http.Error(w, "Invalid limit size", http.StatusBadRequest)
			return
		}

		query := "SELECT id, username, fullname, isactive, mobile_no, bio, gender FROM users WHERE " +
			"username LIKE ? OR fullname LIKE ? OR isactive LIKE ? OR mobile_no LIKE ? OR bio LIKE ? OR gender LIKE ? " +
			"LIMIT ? OFFSET ?"

		rows, err := db.Query(query, "%"+searchQuery+"%", "%"+searchQuery+"%", "%"+searchQuery+"%", "%"+searchQuery+"%", "%"+searchQuery+"%", "%"+searchQuery+"%", limitInt, startInt-1)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			fmt.Println(err)
			return
		}
		defer rows.Close()

		var users []ResponseUser
		for rows.Next() {
			var user ResponseUser
			err := rows.Scan(&user.ID, &user.Username, &user.FullName, &user.IsActive, &user.MobileNo, &user.Bio, &user.Gender)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				fmt.Println(err)
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

func main() {
	// Load TLS certificates
	serverTLSCert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
	if err != nil {
		log.Fatalf("Error loading certificate and key file: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}

	server := http.Server{
		Addr:      ":4443",
		Handler:   http.HandlerFunc(httpRequestHandler),
		TLSConfig: tlsConfig,
	}

	fmt.Printf("Server listening on port 4443...\n")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
