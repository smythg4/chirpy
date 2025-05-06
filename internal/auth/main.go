package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	data, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if len(authHeader) < 1 {
		return "", fmt.Errorf("no bearer token provided")
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer")), nil
}

func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)
	rand.Read(key)
	return hex.EncodeToString(key), nil
}

func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if len(authHeader) < 1 {
		return "", fmt.Errorf("no api key provided")
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, "ApiKey")), nil
}
