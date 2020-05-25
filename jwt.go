package jwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

type Alg string
type Typ string

const JWT Typ  = "JWT"

const (
	HS256 Alg = "HS256"
)

type Header struct {
	Alg Alg `json:"alg, omitempty"`
	Typ Typ `json:"typ, omitempty"`
}

type Payload struct {

}

func GenerateJWTSecret() (string, error) {
	key, err := genRandomBytes(32)
	return hex.EncodeToString(key), err
}

func genRandomBytes(size int) (blk []byte, err error) {
	blk = make([]byte, size)
	_, err = rand.Read(blk)
	return
}

func ToJWTString(header interface{}, payload interface{}) (string, error) {
	hBytes, err := json.Marshal(header)
	if err !=  nil {
		return "", err
	}
	head := b64.StdEncoding.EncodeToString(hBytes)
	head = deletePadding(head)

	bBytes, err := json.Marshal(payload)
	if err !=  nil {
		return "", err
	}
	body := b64.StdEncoding.EncodeToString(bBytes)
	body = deletePadding(body)
	result := head + "." + body
	return result, nil
}

func StructFrom(jwt string, header interface{}, payload interface{}) error {
	strs := strings.Split(jwt, ".")
	if len(strs) < 2 {
		return errors.New("InvalidJWT")
	}
	hDec, err := b64.StdEncoding.DecodeString(addPadding(strs[0]))
	if err !=  nil {
		return err
	}
	err = json.Unmarshal(hDec,header)

	bDec, err := b64.StdEncoding.DecodeString(addPadding(strs[1]))
	if err !=  nil {
		return err
	}
	err = json.Unmarshal(bDec, payload)
	if err !=  nil {
		return err
	}
	return nil
}

func addPadding(src string) string {
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	src = strings.ReplaceAll(src, "-", "+")
	src = strings.ReplaceAll(src, "_", "/")
	return src
}

func deletePadding(src string) string {
	src = strings.ReplaceAll(src, "+", "-")
	src = strings.ReplaceAll(src, "/", "_")
	src = strings.ReplaceAll(src, "=", "")
	return src
}

func Sign(jwt string, secret string) string {
	return jwt + "." + deletePadding(hash(jwt, secret))
}

func Verify(jwt string, secret string) bool {
	str := strings.Split(jwt, ".")
	if len(str) < 3 {
		return false
	}
	return validate(str[0] + "." + str[1], addPadding(str[2]), secret)
}

func hash(src string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(src))
	return b64.StdEncoding.EncodeToString(h.Sum(nil))
}

func validate(value string, hashValue string, secret string) bool {
	return hashValue == hash(value, secret)
}