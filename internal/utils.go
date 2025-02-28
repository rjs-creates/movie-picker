package internal

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

const tokenLength = 32



func HashedPassword(password string) (string, error) {
  hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
      return "", err
    }
    return string(hashedPassword), nil
}

func GenerateToken() (string, error) {
  token := make([]byte, tokenLength)
  if _, err := rand.Read(token); err != nil {
      return "", err
  }
  return base64.URLEncoding.EncodeToString(token), nil
}
