package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

// JWT için gizli anahtar (production'da environment variable kullanın!)
var jwtSecret = []byte("your-secret-key-change-this-in-production")

// Sadece örnek amaçlı: normalde DB'den okursun.
type User struct {
	Email        string
	PasswordHash string
}

var users = map[string]User{
	"test@example.com": {
		Email: "test@example.com",
		// "password123" için yaratılmış hash varsayalım
		PasswordHash: "$2a$10$y8.LpuQNdPy0jFCe89/KgOZ9vKZKCp/sLVDnOpRHBYWc69bOApvIS",
	},
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

// JWT Claims yapısı
type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// JWT token oluşturma fonksiyonu
func generateJWT(email string) (string, error) {
	// Token 24 saat geçerli olacak
	expirationTime := time.Now().Add(24 * time.Hour)

	claims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   email,
		},
	}

	// Token oluştur
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Token'ı imzala ve string'e çevir
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
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

	// JWT token üret
	token, err := generateJWT(user.Email)
	if err != nil {
		http.Error(w, "error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{Token: token})
}

func main() {
	http.HandleFunc("/login", loginHandler)

	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
