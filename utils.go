package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
)

func generateDigest(msg interface{}) []byte {
	bmsg, _ := json.Marshal(msg)
	hash := sha256.Sum256(bmsg)
	return hash[:]
}

func signMessage(msg interface{}, privkey *rsa.PrivateKey) ([]byte, error) {
	dig := generateDigest(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA256, dig)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func verifyDigest(msg interface{}, digest string) bool {
	return hex.EncodeToString(generateDigest(msg)) == digest
}

func verifySignatrue(msg interface{}, sig []byte, pubkey *rsa.PublicKey) (bool, error) {
	dig := generateDigest(msg)
	err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, dig, sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func FileExists(filename string) bool {
	path, _ := filepath.Abs(filename)
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		if os.IsNotExist(err) {
			return false
		}
		fmt.Println(err)
		return false
	}
	return true
}

func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func ReadFileString() string {
	b, err := ioutil.ReadFile("test_30MB.txt") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	return string(b)
}
