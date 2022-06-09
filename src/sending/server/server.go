package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"go-crypto-sending/src/encrypt/diffHellman"
	"go-crypto-sending/src/encrypt/hash"
	"go-crypto-sending/src/encrypt/rc4"
	"go-crypto-sending/src/encrypt/rsa"
	"go-crypto-sending/src/sending"
	"math"
	"math/big"
	"math/rand"
	"net"
	"time"
)

const (
	pk = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvfofOwULOkDnK26iSYdU
vbR7Pmc+beme06wN2HyxXTiFzeQ7OaeBfNbZUAfmKl74BStyDMZy1z7wsI/8kuz+
iqfjlGOn9XWMnsCAVYGfgnAwdrWcPdKYoC01FuQMfasSeBjxkf7I+F2711SovZ44
V4bbcUqx2yDO0W8q3xSHlc7JPhbKOgkMvcKY3IanUWRvphjCB6Oa+U/tm8v1uqqK
nYb5HBY00/rSB2bl8rNZ3iiabbUK6IRm9W+Wz/6Ow18G7SebKU4XcfpaUBmyTF9J
7gBSPyNCEtD1Req8+2h0pwfRdo/+FgtS9CDCgepu3+69/cCvxUFKtFi/DeS8pkkw
Hd1LASe7YmHyjUu8mb8881nUESzY99vVuHWcNIOKByUC3q5syNfGxi9wPdSj63kb
PDXiqvcNkg/8sIAAjnyogCwLA+EBcsxfYAQnOoaLpy7i3epJkw8EQtFB8fgJr46A
TiNK+CBdfhxYYKu9jqGDespxBblJf5GfN9UM0t5Ndkurw82MYYwZP4GAJ+g4WQ3C
is+winvguE6omSu1HnjKvjzQjrTZyMRuDzvEC2rhdpF06EVcHVqQmvuvVwVQn44G
HTBqbi5cep/lrI3SbtgzZ6qt+jk9tODMAjeFI916X3pwxRIFFKf5WjTJGTwRmKHf
MB5itsp7HxnnO5y2Fz6yiRECAwEAAQ==
-----END PUBLIC KEY-----`
	sk = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
)

var (
	p, g, s, selfPubKey, thatPubKey, privkey *big.Int
)

func log(num int, v any) {
	fmt.Printf("[%d]%#v\n", num, v)
}

func send(conn net.Conn, data []byte) error {
	var err error
	defer func(err error) {
		if err != nil {
			panic(err.Error)
		}
	}(err)
	dataHash := hash.Sum(data)
	dataSign, err := rsa.Sign(dataHash[:], []byte(sk))
	buf := new(bytes.Buffer)
	err = binary.Write(buf, sending.ByteOrder, uint32(binary.Size(data)))
	err = binary.Write(buf, sending.ByteOrder, data)
	// _ = binary.Write(buf, sending.ByteOrder, uint32(binary.Size(dataHash)))
	_ = binary.Write(buf, sending.ByteOrder, dataHash)
	_ = binary.Write(buf, sending.ByteOrder, dataSign)
	_, err = conn.Write(buf.Bytes())
	return err
}

func getR2Struct(r1 uint32) []byte {
	var err error
	defer func(err error) {
		if err != nil {
			panic(err.Error)
		}
	}(err)
	rand.Seed(time.Now().UnixMicro())
	r2 := uint32(rand.Intn(math.MaxUint16))
	log(5, r2)
	r12 := fmt.Sprintf("%v%v", r1, r2)
	log(6, r12)
	r12H := hash.Sum([]byte(r12))
	log(7, r12H)
	r12S, err := rsa.Sign(r12H[:], []byte(sk))
	log(8, r12S)
	body := []sending.BodySlice{
		sending.NewBodySlice(r12S),
		sending.NewBodySlice(r2),
	}
	log(9, body)
	return sending.GetBuf(sending.HandShake, body)
}

func getRC4Struct() []byte {
	s, selfPubKey = diffHellman.GenPubKeyUseNumbers(p, g)
	log(15, s)
	log(16, selfPubKey)
	privkey = diffHellman.GenPrivKey(thatPubKey, p, s)
	log(17, privkey)
	body := []sending.BodySlice{sending.NewBodySlice(selfPubKey.Bytes())}
	log(18, body)
	return sending.GetBuf(sending.RC4, body)
}

// 2
func receiveHandShake(conn net.Conn) {
	var err error
	reader := bufio.NewReader(conn)
	encData, err := sending.ParseBuf(reader, sending.ClientSide)
	log(1, encData.String())
	decData, err := rsa.Decrypt(encData.EncData, []byte(sk))
	log(2, decData)
	message, err := sending.ParseMessage(bytes.NewReader(decData))
	log(3, message)
	if message.Head.Type == sending.HandShake {
		r1b := message.Body[0].Value
		r1 := sending.ByteOrder.Uint32(r1b)
		log(4, r1)
		if err != nil {
			panic(err.Error())
		}
		sendHanShake(conn, r1)
	}
}

// 3
func sendHanShake(conn net.Conn, r1 uint32) {
	r2 := getR2Struct(r1)
	err := send(conn, r2)
	if err != nil {
		panic(err.Error())
	}
	receiveRC4(conn)
}

// 6
func receiveRC4(conn net.Conn) {
	var err error
	reader := bufio.NewReader(conn)
	encData, err := sending.ParseBuf(reader, sending.ClientSide)
	log(10, encData)
	message, err := sending.ParseMessage(bytes.NewReader(encData.EncData))
	log(11, message)
	if message.Head.Type == sending.RC4 {
		pD, _ := rsa.Decrypt(message.Body[0].Value, []byte(sk))
		gD, _ := rsa.Decrypt(message.Body[1].Value, []byte(sk))
		kD, _ := rsa.Decrypt(message.Body[2].Value, []byte(sk))
		p = new(big.Int).SetBytes(pD)
		log(12, p)
		g = new(big.Int).SetBytes(gD)
		log(13, g)
		thatPubKey = new(big.Int).SetBytes(kD)
		log(14, thatPubKey)
		if err != nil {
			panic(err.Error())
		}
		sendRC4(conn)
	}
}

// 7
func sendRC4(conn net.Conn) {
	rc4s := getRC4Struct()
	err := send(conn, rc4s)
	if err != nil {
		panic(err.Error())
	}
	receiveFile(conn)
}

// 10
func receiveFile(conn net.Conn) {
	var err error
	defer func(err error) {
		if err != nil {
			panic(err.Error)
		}
	}(err)
	reader := bufio.NewReader(conn)
	data, err := sending.ParseBuf(reader, sending.ClientSide)
	edata, err := sending.ParseMessage(bytes.NewReader(data.EncData))
	if edata.Head.Type == sending.SendMessage {
		rc4data := edata.Body[0].Value
		fmt.Printf("数据（密文）：%x\n", rc4data)
		key := privkey.Bytes()[:256]
		cipher, _ := rc4.NewCipher(key)
		cipher.XORKeyStream(rc4data, rc4data)
		fmt.Printf("数据（编码）：%x\n", rc4data)
		fmt.Printf("数据（明文）：%s\n", string(rc4data))
	}
	if err != nil {
		fmt.Println("接收错误: ", err.Error())
	}

}

func Handle(conn net.Conn) {
	receiveHandShake(conn)
}
