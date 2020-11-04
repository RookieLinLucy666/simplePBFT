package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

var privateKey8080 *rsa.PrivateKey
var privateKey8081 *rsa.PrivateKey
var privateKey8082 *rsa.PrivateKey
var privateKey8083 *rsa.PrivateKey

var privateKey8084 *rsa.PrivateKey
var privateKey8085 *rsa.PrivateKey
var privateKey8086 *rsa.PrivateKey
var privateKey8087 *rsa.PrivateKey

var publicKey8080 *rsa.PublicKey
var publicKey8081 *rsa.PublicKey
var publicKey8082 *rsa.PublicKey
var publicKey8083 *rsa.PublicKey

var publicKey8084 *rsa.PublicKey
var publicKey8085 *rsa.PublicKey
var publicKey8086 *rsa.PublicKey
var publicKey8087 *rsa.PublicKey

var privateKeyClient8088 *rsa.PrivateKey
var publicKeyClient8088 *rsa.PublicKey
var privateKeyClient8089 *rsa.PrivateKey
var publicKeyClient8089 *rsa.PublicKey
var privateKeyClient8090 *rsa.PrivateKey
var publicKeyClient8090 *rsa.PublicKey
var privateKeyClient8091 *rsa.PrivateKey
var publicKeyClient8091 *rsa.PublicKey
var privateKeyClient8092 *rsa.PrivateKey
var publicKeyClient8092 *rsa.PublicKey
var privateKeyClient8093 *rsa.PrivateKey
var publicKeyClient8093 *rsa.PublicKey
var privateKeyClient8094 *rsa.PrivateKey
var publicKeyClient8094 *rsa.PublicKey
var privateKeyClient8095 *rsa.PrivateKey
var publicKeyClient8095 *rsa.PublicKey

var KnownAllNodes []*KnownNode
var KnownGovNodes []*KnownNode
var KnownNorNodes []*KnownNode
var KeypairMap map[int]Keypair
var ClientNode *KnownNode
var DestNode []*KnownNode

func init() {
	var err error
	generateKeyFiles()
	privateKey8080, publicKey8080, err = getKeyPairByFile(0)
	if err != nil {
		panic(err)
	}
	privateKey8081, publicKey8081, err = getKeyPairByFile(1)
	if err != nil {
		panic(err)
	}
	privateKey8082, publicKey8082, err = getKeyPairByFile(2)
	if err != nil {
		panic(err)
	}
	privateKey8083, publicKey8083, err = getKeyPairByFile(3)
	if err != nil {
		panic(err)
	}

	privateKey8084, publicKey8084, err = getKeyPairByFile(4)
	if err != nil {
		panic(err)
	}
	privateKey8085, publicKey8085, err = getKeyPairByFile(5)
	if err != nil {
		panic(err)
	}
	privateKey8086, publicKey8086, err = getKeyPairByFile(6)
	if err != nil {
		panic(err)
	}
	privateKey8087, publicKey8087, err = getKeyPairByFile(7)
	if err != nil {
		panic(err)
	}

	privateKeyClient8088, publicKeyClient8088, err = getKeyPairByFile(8)
	if err != nil {
		panic(err)
	}
	privateKeyClient8089, publicKeyClient8089, err = getKeyPairByFile(9)
	if err != nil {
		panic(err)
	}
	privateKeyClient8090, publicKeyClient8090, err = getKeyPairByFile(10)
	if err != nil {
		panic(err)
	}
	privateKeyClient8091, publicKeyClient8091, err = getKeyPairByFile(11)
	if err != nil {
		panic(err)
	}
	privateKeyClient8092, publicKeyClient8092, err = getKeyPairByFile(12)
	if err != nil {
		panic(err)
	}
	privateKeyClient8093, publicKeyClient8093, err = getKeyPairByFile(13)
	if err != nil {
		panic(err)
	}
	privateKeyClient8094, publicKeyClient8094, err = getKeyPairByFile(14)
	if err != nil {
		panic(err)
	}
	privateKeyClient8095, publicKeyClient8095, err = getKeyPairByFile(15)
	if err != nil {
		panic(err)
	}

	KnownAllNodes = []*KnownNode{
		{
			0,
			"localhost:8080",
			publicKey8080,
		},
		{
			1,
			"localhost:8081",
			publicKey8081,
		},
		{
			2,
			"localhost:8082",
			publicKey8082,
		},
		{
			3,
			"localhost:8083",
			publicKey8083,
		},

		{
			4,
			"localhost:8084",
			publicKey8084,
		},
		{
			5,
			"localhost:8085",
			publicKey8085,
		},
		{
			6,
			"localhost:8086",
			publicKey8086,
		},
		{
			7,
			"localhost:8087",
			publicKey8087,
		},
	}
	KnownGovNodes = KnownAllNodes[:4]
	KnownNorNodes = KnownAllNodes[4:]
	KeypairMap = map[int]Keypair{
		0: {
			privateKey8080,
			publicKey8080,
		},
		1: {
			privateKey8081,
			publicKey8081,
		},
		2: {
			privateKey8082,
			publicKey8082,
		},
		3: {
			privateKey8083,
			publicKey8083,
		},
		4: {
			privateKey8084,
			publicKey8084,
		},
		5: {
			privateKey8085,
			publicKey8085,
		},
		6: {
			privateKey8086,
			publicKey8086,
		},
		7: {
			privateKey8087,
			publicKey8087,
		},
		8: {
			privateKeyClient8088,
			publicKeyClient8088,
		},
		9: {
			privateKeyClient8089,
			publicKeyClient8089,
		},
		10: {
			privateKeyClient8090,
			publicKeyClient8090,
		},
		11: {
			privateKeyClient8091,
			publicKeyClient8091,
		},
		12: {
			privateKeyClient8092,
			publicKeyClient8092,
		},
		13: {
			privateKeyClient8093,
			publicKeyClient8093,
		},
		14: {
			privateKeyClient8094,
			publicKeyClient8094,
		},
		15: {
			privateKeyClient8095,
			publicKeyClient8095,
		},
	}
	ClientNode = &KnownNode{
		8,
		"localhost:8088",
		publicKeyClient8088,
	}
	DestNode = []*KnownNode{
		{
			9,
			"localhost:8089",
			publicKeyClient8089,
		},
		{
			10,
			"localhost:8090",
			publicKeyClient8090,
		},
		{
			11,
			"localhost:8091",
			publicKeyClient8091,
		},
		{
			12,
			"localhost:8092",
			publicKeyClient8092,
		},
		{
			13,
			"localhost:8093",
			publicKeyClient8093,
		},
		{
			14,
			"localhost:8094",
			publicKeyClient8094,
		},
		{
			15,
			"localhost:8095",
			publicKeyClient8095,
		},
	}
}

func getKeyPairByFile(nodeID int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privFile, _ := filepath.Abs(fmt.Sprintf("./Keys/%d_priv", nodeID))
	pubFile, _ := filepath.Abs(fmt.Sprintf("./Keys/%d_pub", nodeID))
	fbytes, err := ioutil.ReadFile(privFile)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(fbytes)
	if block == nil {
		return nil, nil, fmt.Errorf("parse block occured error")
	}
	privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pubfbytes, err := ioutil.ReadFile(pubFile)
	if err != nil {
		return nil, nil, err
	}
	pubblock, _ := pem.Decode(pubfbytes)
	if pubblock == nil {
		return nil, nil, fmt.Errorf("parse block occured error")
	}
	pubkey, err := x509.ParsePKIXPublicKey(pubblock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return privkey, pubkey.(*rsa.PublicKey), nil
}

func generateKeyFiles() {
	if !FileExists("./Keys") {
		err := os.Mkdir("Keys", 0700)
		if err != nil {
			panic(err)
		}
		for i := 0; i < 16; i++ {
			filename, _ := filepath.Abs(fmt.Sprintf("./Keys/%d", i))
			if !FileExists(filename+"_priv") && !FileExists(filename+"_pub") {
				priv, pub := generateKeyPair()
				err := ioutil.WriteFile(filename+"_priv", priv, 0644)
				if err != nil {
					panic(err)
				}
				ioutil.WriteFile(filename+"_pub", pub, 0644)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

func generateKeyPair() ([]byte, []byte) {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	mprivkey := x509.MarshalPKCS1PrivateKey(privkey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: mprivkey,
	}
	bprivkey := pem.EncodeToMemory(block)
	pubkey := &privkey.PublicKey
	mpubkey, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: mpubkey,
	}
	bpubkey := pem.EncodeToMemory(block)
	return bprivkey, bpubkey
}
