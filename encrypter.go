package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"os"
)

func main() {
	//declarations
	reader := bufio.NewReader(os.Stdin)
	iv := make([]byte, 12)

	//get password
	fmt.Print("Password: ")
	password, _ := reader.ReadBytes('\n') //ignore errors for now

	//get file to encrypt
	fmt.Print("File to Encrypt: ")
	path, _ := reader.ReadString('\n')
	plaintext, _ := ioutil.ReadFile(path[:len(path) - 1])

	//create iv/salt
	rand.Read(iv)

	//create key from password using SHA-256 (agreed)
	dk := pbkdf2.Key(password[:len(password) - 1], iv, 1000, 32, sha256.New)

	//create aes gcm cipher
	blk, _ := aes.NewCipher(dk)
	gcm, _ := cipher.NewGCM(blk)

	//encrypt
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	_ = ioutil.WriteFile("encrypted.html", []byte(base64.StdEncoding.EncodeToString(ciphertext)), 0744)

	//output necessary information to decrypt the file
	fmt.Printf("IV: %s\n", base64.StdEncoding.EncodeToString(iv))
	fmt.Println("Encrypted file: encrypted.html")
}
