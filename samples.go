package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"time"
)

type sampleConf struct {
	Port          string
	CrtPemUrl     string
	RootPemUrl    string
	PrivateKeyUrl string
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: error: %s", err.Error())
		os.Exit(1)
	}
}

func encryptWrite(conn *net.TCPConn, cipherBlock cipher.Block, plainText []byte) error {

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	initializationVector := ciphertext[:aes.BlockSize]
	_, err := io.ReadFull(rand.Reader, initializationVector)

	if err != nil {
		return err
	}

	stream := cipher.NewCTR(cipherBlock, initializationVector)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainText)

	_, err = conn.Write(ciphertext)

	return err
}

func decryptRead(conn *net.TCPConn, cipherBlock cipher.Block, bufSize int) ([]byte, error) {
	if bufSize == 0 {
		bufSize = 8192
	}

	cipherMessage := make([]byte, bufSize)
	cipherLen, err := conn.Read(cipherMessage)
	if err != nil {
		return []byte(""), err
	}

	message := make([]byte, cipherLen-aes.BlockSize)
	stream := cipher.NewCTR(cipherBlock, cipherMessage[:aes.BlockSize])
	stream.XORKeyStream(message, cipherMessage[aes.BlockSize:cipherLen])

	return message, nil
}

func handleClient(conn *net.TCPConn, privateKey *rsa.PrivateKey, rootPem, crtPem []byte) {
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	fmt.Println("client accept!")

	conn.Write(rootPem)

	responseBuf := make([]byte, 5)
	responseLen, err := conn.Read(responseBuf)
	checkError(err)
	if string(responseBuf[:responseLen]) != "ok" {
		panic("failed to parse root pem")
	}

	conn.Write(crtPem)

	cryptoKey := make([]byte, 1024)
	cryptoKeyLen, err := conn.Read(cryptoKey)
	checkError(err)

	conn.Write([]byte("ok"))

	sessionKey := make([]byte, 32)
	err = rsa.DecryptPKCS1v15SessionKey(rand.Reader, privateKey, cryptoKey[:cryptoKeyLen], sessionKey)
	checkError(err)

	cipherBlock, err := aes.NewCipher(sessionKey)
	checkError(err)

	message, err := decryptRead(conn, cipherBlock, 8192)
	checkError(err)

	fmt.Println("client message: " + string(message))
	responseMessage := string(message) + " too!"

	err = encryptWrite(conn, cipherBlock, []byte(responseMessage))
	checkError(err)
	time.Sleep(1000 * time.Millisecond)
}

func main() {
	configFile, err := os.Open("sample.json")
	checkError(err)
	decoder := json.NewDecoder(configFile)
	var config sampleConf
	err = decoder.Decode(&config)
	checkError(err)
	defer configFile.Close()

	rootPem, err := ioutil.ReadFile(config.RootPemUrl)
	checkError(err)

	crtPem, err := ioutil.ReadFile(config.CrtPemUrl)
	checkError(err)

	pkData, err := ioutil.ReadFile(config.PrivateKeyUrl)
	checkError(err)

	block, _ := pem.Decode(pkData)
	if block == nil {
		panic("fail to decode private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	checkError(err)

	service := ":" + config.Port
	tcpAddr, err := net.ResolveTCPAddr("tcp", service)
	checkError(err)
	listner, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)
	for {
		conn, err := listner.AcceptTCP()
		if err != nil {
			continue
		}

		go handleClient(conn, privateKey, rootPem, crtPem)
	}
}
