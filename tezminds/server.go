package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type Password struct {
	CurrentPassword string `json:"currentpassword"`
	NewPassword     string `json:"newpassword"`
}

type User struct {
	Userid    int    `json:"userid"`
	Email     string `json:"email"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Password  string `json:"password"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type GetUser struct {
	Userid    int    `json:"userid"`
	Email     string `json:"email"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	CreatedAt string `json:"created_at"`
}

type UserResponse struct {
	ErrorCode    int         `json:"errorCode"`
	ErrorMessage string      `json:"errorMessage"`
	Data         interface{} `json:"data"`
}

type getAllUsersResponse struct {
	ErrorCode    int         `json:"errorCode"`
	ErrorMessage string      `json:"errorMessage"`
	Data         interface{} `json:"data"`
}

type getAllUsersData struct {
	Count   int         `json:"count"`
	Records interface{} `json:"records"`
}

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	ErrorCode       int    `json:"errorCode"`
	ErrorMessage    string `json:"errorMessage"`
	ResponseMessage string `json:"responseMessage"`
	Token           string `json:"token"`
}

type UserInfo struct {
	UserInfoId   int    `json:"userinfoid"`
	UserId       int    `json:"userid"`
	MobileNumber int    `json:"mobilenumber"`
	Bio          string `json:"bio"`
	Address      string `json:"address"`
	Experience   int    `json:"experience"`
	Image        string `json:"image"`
	PortfolioUrl string `json:"portfoliourl"`
	FaceBookUrl  string `json:"facebookurl"`
	TwitterUrl   string `json:"twitterurl"`
	InstagramUrl string `json:"instagramurl"`
}

type ResponseUserInfo struct {
	UserId       int    `json:"userid"`
	FirstName    string `json:"firstname"`
	LastName     string `json:"lastname"`
	Email        string `json:"email"`
	MobileNumber int    `json:"mobilenumber"`
	Bio          string `json:"bio"`
	Address      string `json:"address"`
	Experience   int    `json:"experience"`
	Image        string `json:"image"`
	PortfolioUrl string `json:"portfoliourl"`
	FaceBookUrl  string `json:"facebookurl"`
	TwitterUrl   string `json:"twitterurl"`
	InstagramUrl string `json:"instagramurl"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type UserIdClaims struct {
	jwt.StandardClaims
	Userid int `json:"u,omitempty"`
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
	r.HandleFunc("/welcome", welcome).Methods("GET")
	r.HandleFunc("/users", getAllUsers).Methods("GET")
	r.HandleFunc("/user", getLoginUserInfo).Methods("GET")
	r.HandleFunc("/update", updateUser).Methods("GET")
	r.HandleFunc("/user", addUser).Methods("POST")
	r.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/user", updateUser).Methods("PUT")
	r.HandleFunc("/updatepassword", changePassword).Methods("POST")

	http.ListenAndServe("localhost"+":"+"8080", r)

}

func getLoginUserInfo(w http.ResponseWriter, r *http.Request) {
	isVerified, userid := verifyToken(w, r)
	if isVerified {
		row := db.QueryRow("SELECT * FROM users WHERE userid = ?", userid)
		row2 := db.QueryRow("SELECT * FROM userinfo WHERE userid = ?", userid)

		var user User
		var userinfo UserInfo

		err := row.Scan(&user.Userid, &user.Email, &user.Firstname, &user.Lastname, &user.Password, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			fmt.Println("Error : ", err.Error())

			json.NewEncoder(w).Encode(err.Error())
			return
		}

		err2 := row2.Scan(&userinfo.UserInfoId, &userinfo.UserId, &userinfo.MobileNumber, &userinfo.Bio, &userinfo.Address, &userinfo.Experience, &userinfo.Image, &userinfo.PortfolioUrl, &userinfo.FaceBookUrl, &userinfo.TwitterUrl, &userinfo.InstagramUrl)
		if err2 != nil {
			fmt.Println("Error : ", err.Error())

			json.NewEncoder(w).Encode(err.Error())
			return
		}

		type ResponseUserInfo struct {
			UserId       int    `json:"userid"`
			FirstName    string `json:"firstname"`
			LastName     string `json:"lastname"`
			Email        string `json:"email"`
			MobileNumber int    `json:"mobilenumber"`
			Bio          string `json:"bio"`
			Address      string `json:"address"`
			Experience   int    `json:"experience"`
			Image        string `json:"image"`
			PortfolioUrl string `json:"portfoliourl"`
			FaceBookUrl  string `json:"facebookurl"`
			TwitterUrl   string `json:"twitterurl"`
			InstagramUrl string `json:"instagramurl"`
			CreatedAt    string `json:"created_at"`
			UpdatedAt    string `json:"updated_at"`
		}

		responseUserInfo := ResponseUserInfo{
			UserId:       user.Userid,
			FirstName:    user.Firstname,
			LastName:     user.Lastname,
			Email:        user.Email,
			MobileNumber: userinfo.MobileNumber,
			Bio:          userinfo.Bio,
			Address:      userinfo.Address,
			Experience:   userinfo.Experience,
			Image:        userinfo.Image,
			PortfolioUrl: userinfo.PortfolioUrl,
			FaceBookUrl:  userinfo.FaceBookUrl,
			TwitterUrl:   userinfo.TwitterUrl,
			InstagramUrl: userinfo.InstagramUrl,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
		}

		json.NewEncoder(w).Encode(responseUserInfo)

	} else {
		json.NewEncoder(w).Encode("You are not autherised")
	}
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	isVerified, userid := verifyToken(w, r)
	if isVerified {
		row := db.QueryRow("SELECT * FROM users WHERE userid = ?", userid)

		var user User

		err := row.Scan(&user.Userid, &user.Email, &user.Firstname, &user.Lastname, &user.Password, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			fmt.Println("Error : ", err.Error())

			json.NewEncoder(w).Encode(err.Error())
			return
		}

		decoder := json.NewDecoder(r.Body)

		if err := decoder.Decode(&user); err != nil {
			json.NewEncoder(w).Encode("error")
			return
		}

		hash, _ := HashPassword(user.Password)

		fmt.Println("line 138 ", user)

		_, err = db.Exec("UPDATE users SET email=?, firstname=?, password=?, lastname=? WHERE userid =?", user.Email, user.Firstname, hash, user.Lastname, userid)
		if err != nil {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: err.Error(),
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		getUser := GetUser{
			Userid:    user.Userid,
			Email:     user.Email,
			Firstname: user.Firstname,
			Lastname:  user.Lastname,
			CreatedAt: user.CreatedAt,
		}
		if err != nil {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: "No such user found!",
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		}
		json.NewEncoder(w).Encode(getUser)

	} else {
		json.NewEncoder(w).Encode("You are not autherised")
	}
}

func welcome(w http.ResponseWriter, r *http.Request) {
	isVerified, _ := verifyToken(w, r)

	if isVerified {
		json.NewEncoder(w).Encode("Welcome User")
	} else {
		json.NewEncoder(w).Encode("You are not autherised")
	}

}

func login(w http.ResponseWriter, r *http.Request) {
	var login Login
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&login); err != nil {
		response := UserResponse{
			ErrorCode:    1,
			ErrorMessage: err.Error(),
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	defer r.Body.Close()
	email := login.Email
	row := db.QueryRow("SELECT * FROM users WHERE email = ?", email)

	var user User

	err := row.Scan(&user.Userid, &user.Email, &user.Firstname, &user.Lastname, &user.Password, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		fmt.Println("Error : ", err.Error())

		json.NewEncoder(w).Encode(err.Error())
		return
	}

	match := CheckPasswordHash(login.Password, user.Password)
	if match {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"userId": user.Userid,
			"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		})
		secretkey := []byte("JWT_SECRET_KEY")

		tokenString, _ := token.SignedString(secretkey)

		response := LoginResponse{
			ErrorCode:       0,
			ErrorMessage:    "",
			ResponseMessage: "Login successful!",
			Token:           tokenString,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		response := LoginResponse{
			ErrorCode:    1,
			ErrorMessage: "Incorrect password",
			Token:        "",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}

}

func getAllUsers(w http.ResponseWriter, r *http.Request) {
	queryMap := r.URL.Query()

	if len(queryMap) == 0 {
		rows, err := db.Query("SELECT * FROM users")
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

		var responseUserInfos []ResponseUserInfo

		getAllUsersHelper(w, r, responseUserInfos)

	} else {
		search := r.URL.Query().Get("search")
		start := r.URL.Query().Get("start") // current page
		limit := r.URL.Query().Get("limit") // users/page

		if start == "" {
			start = "1"
		}

		if limit == "" {
			limit = "5"
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

		query := "SELECT userid, firstname, lastname, email, created_at from users WHERE " +
			" userid LIKE ? OR firstname LIKE ? OR lastname LIKE ? OR email LIKE ?  OR created_at LIKE ? " +
			"LIMIT ? OFFSET ?"

		rows, err := db.Query(query, "%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%", limitInt, startInt-1)

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

		var getUsers []GetUser

		for rows.Next() {
			var user User

			rows.Scan(&user.Userid, &user.Firstname, &user.Lastname, &user.Email, &user.CreatedAt)

			// fmt.Println("user ", user)

			getUser := GetUser{
				Userid:    user.Userid,
				Email:     user.Email,
				Firstname: user.Firstname,
				Lastname:  user.Lastname,
				CreatedAt: user.CreatedAt,
			}

			getUsers = append(getUsers, getUser)

			if err != nil {
				response := UserResponse{
					ErrorCode:    1,
					ErrorMessage: err.Error(),
					Data:         nil,
				}
				json.NewEncoder(w).Encode(response)
				return
			}

		}
		if len(getUsers) == 0 {
			response := UserResponse{
				ErrorCode:    0,
				ErrorMessage: "Database is Empty!",
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getUsers)

	}

}

func addUser(w http.ResponseWriter, r *http.Request) {
	var user User
	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(&user); err != nil {
		json.NewEncoder(w).Encode("error")
		return
	}
	addUserHelper(w, r, user)

}

func addUserHelper(w http.ResponseWriter, r *http.Request, user User) {

	hashPass, _ := HashPassword(user.Password)

	_, err := db.Exec("INSERT INTO users (email, firstname, lastname, password) VALUES (?, ? ,? , ?)", user.Email, user.Firstname, user.Lastname, hashPass)
	// _,err := db.Exec("INSERT INTO userifo (userid  (?)", user.Userid)

	if err != nil {
		json.NewEncoder(w).Encode("unable to add user ")
	}

	defer r.Body.Close()

	row := db.QueryRow("Select * from users WHERE email = ?", user.Email)
	var updatedUser User

	row.Scan(&updatedUser.Userid, &updatedUser.Email, &updatedUser.Firstname, &updatedUser.Lastname, &updatedUser.Password, &updatedUser.CreatedAt, &updatedUser.UpdatedAt)

	fmt.Println("getuser ", updatedUser.Userid)

	_, err2 := db.Exec("INSERT INTO userinfo (userid ) VALUES (?)", updatedUser.Userid)

	if err2 != nil {
		json.NewEncoder(w).Encode("unable to add user ")
		return
	}

	getUser := GetUser{
		Userid:    updatedUser.Userid,
		Email:     updatedUser.Email,
		Firstname: updatedUser.Firstname,
		Lastname:  updatedUser.Lastname,
		CreatedAt: updatedUser.CreatedAt,
	}

	json.NewEncoder(w).Encode(getUser)
	return
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	isVerified, userid := verifyToken(w, r)
	if isVerified {
		row := db.QueryRow("SELECT * FROM users WHERE userid = ?", userid)

		var user User

		err := row.Scan(&user.Userid, &user.Email, &user.Firstname, &user.Lastname, &user.Password, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			fmt.Println("Error : ", err.Error())

			json.NewEncoder(w).Encode(err.Error())
			return
		}

		var passwordstruct Password
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&passwordstruct); err != nil {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: err.Error(),
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		}
		defer r.Body.Close()

		isCurrentPasswordRight := CheckPasswordHash(passwordstruct.CurrentPassword, user.Password)

		if !isCurrentPasswordRight {
			response := UserResponse{
				ErrorCode:    1,
				ErrorMessage: "current password is incorrect",
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		} else {

			hashedNewPass, _ := HashPassword(passwordstruct.NewPassword)
			_, err = db.Exec("UPDATE users SET password=? WHERE userid =?", hashedNewPass, userid)
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
				ErrorMessage: "password updated successfully",
				Data:         nil,
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// ch

		// json.NewEncoder(w).Encode(responseUserInfo)

	} else {
		json.NewEncoder(w).Encode("You are not autherised")
	}

}

func getAllUsersHelper(w http.ResponseWriter, r *http.Request, reponseUserInfos []ResponseUserInfo) {
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

	for rows.Next() {
		var user User

		rows.Scan(&user.Userid, &user.Email, &user.Firstname, &user.Lastname, &user.Password, &user.CreatedAt, &user.UpdatedAt)

		// fmt.Println("getuser ", updatedUser)
		row2 := db.QueryRow("SELECT * FROM userinfo WHERE userid = ?", user.Userid)
		var userinfo UserInfo

		err2 := row2.Scan(&userinfo.UserInfoId, &userinfo.UserId, &userinfo.MobileNumber, &userinfo.Bio, &userinfo.Address, &userinfo.Experience, &userinfo.Image, &userinfo.PortfolioUrl, &userinfo.FaceBookUrl, &userinfo.TwitterUrl, &userinfo.InstagramUrl)

		if err2 != nil {
			fmt.Println("Error : ", err.Error())

			json.NewEncoder(w).Encode(err.Error())
			return
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

		responseUserInfo := ResponseUserInfo{
			UserId:       user.Userid,
			FirstName:    user.Firstname,
			LastName:     user.Lastname,
			Email:        user.Email,
			MobileNumber: userinfo.MobileNumber,
			Bio:          userinfo.Bio,
			Address:      userinfo.Address,
			Experience:   userinfo.Experience,
			Image:        userinfo.Image,
			PortfolioUrl: userinfo.PortfolioUrl,
			FaceBookUrl:  userinfo.FaceBookUrl,
			TwitterUrl:   userinfo.TwitterUrl,
			InstagramUrl: userinfo.InstagramUrl,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
		}
		reponseUserInfos = append(reponseUserInfos, responseUserInfo)
	}
	if len(reponseUserInfos) == 0 {
		response := UserResponse{
			ErrorCode:    0,
			ErrorMessage: "Database is Empty!",
			Data:         nil,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	getAllUsersData := getAllUsersData{
		Count:   len(reponseUserInfos),
		Records: reponseUserInfos,
	}

	getAllUsersResponse := getAllUsersResponse{
		ErrorCode:    0,
		ErrorMessage: "",
		Data:         getAllUsersData,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getAllUsersResponse)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func verifyToken(w http.ResponseWriter, r *http.Request) (bool, interface{}) {

	var userid interface{}

	if r.Header["Authorization"] != nil {
		header := r.Header["Authorization"]

		tokenString := strings.SplitAfterN(header[0], " ", 2)[1]

		secretkey := []byte("JWT_SECRET_KEY")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			return secretkey, nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			fmt.Println("User : ", claims["userId"])
			userid = claims["userId"]
			return true, userid
		} else {
			fmt.Println(err)
			return false, nil
		}
	} else {
		return false, nil
	}
}
