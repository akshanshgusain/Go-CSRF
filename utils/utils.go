package utils

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandomBytes(s int) ([]byte, error) {
	b := make([]byte, s)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}
