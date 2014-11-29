package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	_ "github.com/lib/pq"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"time"
)

type dbConf struct {
	User   string
	Pass   string
	DBName string
}

type sampleConf struct {
	Port          string
	CrtPemUrl     string
	RootPemUrl    string
	PrivateKeyUrl string
	DBConf        dbConf
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: error: %s", err.Error())
		os.Exit(1)
	}
}

func encryptWrite(conn *net.TCPConn, cipherBlock cipher.Block, plainText []byte) error {

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]
	_, err := io.ReadFull(rand.Reader, iv)

	if err != nil {
		return err
	}

	stream := cipher.NewCTR(cipherBlock, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainText)

	_, err = conn.Write(ciphertext)

	return err
}

func decryptRead(conn *net.TCPConn, cipherBlock cipher.Block, bufSize int) ([]byte, error) {
	if bufSize == 0 {
		bufSize = 8192
	}

	cipherMsg := make([]byte, bufSize)
	cipherLen, err := conn.Read(cipherMsg)
	if err != nil {
		return []byte(""), err
	}

	msg := make([]byte, cipherLen-aes.BlockSize)
	stream := cipher.NewCTR(cipherBlock, cipherMsg[:aes.BlockSize])
	stream.XORKeyStream(msg, cipherMsg[aes.BlockSize:cipherLen])

	return msg, nil
}

func handleClient(conn *net.TCPConn, db *sql.DB, privateKey *rsa.PrivateKey, rootPem, crtPem []byte) {
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

	msg, err := decryptRead(conn, cipherBlock, 8192)
	checkError(err)

	fmt.Println("client msg: " + string(msg))

	cnt := 0
	err = db.QueryRow("SELECT COUNT(*) AS cnt FROM word_counts WHERE word = $1;", string(msg)).Scan(&cnt)
	checkError(err)

	if cnt == 0 {
		err = encryptWrite(conn, cipherBlock, []byte("'"+string(msg)+"'...わたし、気になります！"))
		checkError(err)
		_, err = db.Exec("INSERT INTO word_counts(word, num) VALUES($1, 1);", string(msg))
		checkError(err)
	} else {
		num := 0
		err = db.QueryRow("SELECT num FROM word_counts WHERE word = $1;", string(msg)).Scan(&num)
		checkError(err)

		err = encryptWrite(conn, cipherBlock, []byte("'"+string(msg)+"'はもう"+strconv.Itoa(num+1)+"回も聞いたのでわたし、気になりません！"))
		checkError(err)
		_, err = db.Exec("UPDATE word_counts SET num = $1 WHERE word = $2;", num+1, string(msg))
		checkError(err)
	}
}

func main() {
	configFile, err := os.Open("sample.json")
	checkError(err)
	decoder := json.NewDecoder(configFile)
	var config sampleConf
	err = decoder.Decode(&config)
	checkError(err)
	defer configFile.Close()

	db, err := sql.Open("postgres", "user="+config.DBConf.User+" dbname="+config.DBConf.DBName+" password="+config.DBConf.Pass+" sslmode=disable")
	checkError(err)
	defer db.Close()

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

		go handleClient(conn, db, privateKey, rootPem, crtPem)
	}
}
