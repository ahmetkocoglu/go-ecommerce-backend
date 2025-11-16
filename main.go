package main

import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// Sadece örnek amaçlı: normalde DB'den okursun.
type User struct {
	Email        string
	PasswordHash string
}

var users = map[string]User{
	"test@example.com": {
		Email: "test@example.com",
		// "password123" için yaratılmış hash varsayalım
		PasswordHash: "$2a$10$CiQFHXMS5uOBwH2vwT3ghOZ1ZxJmN3TgRjkBvw0n2.DrV6L5q8p5a",
	},
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	user, ok := users[req.Email]
	if !ok {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Şifre doğrulama
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Gerçekte burada JWT veya benzeri token üretmen gerekir.
	token := "fake-jwt-token-example"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{Token: token})
}

func main() {
	http.HandleFunc("/login", loginHandler)

	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
