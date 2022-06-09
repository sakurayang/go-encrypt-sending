package client

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
	"os"
	"time"
)

var (
	p, g, s, selfPubKey, thatPubKey, privkey *big.Int
	r1                                       uint32
)

const pk = `-----BEGIN PUBLIC KEY-----
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

func log(num int, v any) {
	fmt.Printf("[%d]%#v\n", num, v)
}

func send(conn net.Conn, data []byte, encrypt bool) error {
	var err error
	var sd []byte
	if encrypt {
		sd, err = rsa.Encrypt(data, []byte(pk))
	} else {
		sd = data
	}
	dataHash := hash.Sum(sd)
	buf := new(bytes.Buffer)
	err = binary.Write(buf, sending.ByteOrder, uint32(binary.Size(sd)))
	err = binary.Write(buf, sending.ByteOrder, sd)
	// _ = binary.Write(buf, sending.ByteOrder, uint32(binary.Size(dataHash)))
	err = binary.Write(buf, sending.ByteOrder, dataHash)
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		panic(err.Error())
	}
	return err
}

func getR1Struct() []byte {
	rand.Seed(time.Now().UnixMicro())
	r1 = uint32(rand.Intn(math.MaxUint16))
	log(1, r1)
	body := []sending.BodySlice{sending.NewBodySlice(r1)}
	log(2, body)
	return sending.GetBuf(sending.HandShake, body)
}

func getRC4Struct() []byte {
	p, g, s, selfPubKey = diffHellman.GenKeys()
	log(10, p)
	log(11, g)
	log(12, s)
	log(13, selfPubKey)
	pE, err := rsa.Encrypt(p.Bytes(), []byte(pk))
	gE, err := rsa.Encrypt(g.Bytes(), []byte(pk))
	kE, err := rsa.Encrypt(selfPubKey.Bytes(), []byte(pk))

	body := []sending.BodySlice{
		sending.NewBodySlice(pE),
		sending.NewBodySlice(gE),
		sending.NewBodySlice(kE),
	}
	log(14, body)
	if err != nil {
		panic(err.Error())
	}
	return sending.GetBuf(sending.RC4, body)
}

// 1
func sendHandshake(conn net.Conn) {
	r1s := getR1Struct()
	log(3, r1s)
	err := send(conn, r1s, true)
	if err != nil {
		panic(err.Error())
	}
	receiveHandShake(conn)
}

// 4
func receiveHandShake(conn net.Conn) {
	var err error
	reader := bufio.NewReader(conn)
	data, err := sending.ParseBuf(reader, sending.ServerSide)
	log(4, data)
	message, err := sending.ParseMessage(bytes.NewReader(data.EncData))
	log(5, message)
	e := rsa.SignVer(data.Checksum[:], data.Sign, []byte(pk))
	if e != nil {
		panic("verify sign error")
	}

	if message.Head.Type == sending.HandShake {
		rsign := message.Body[0].Value
		log(6, rsign)
		r2 := message.Body[1].Value
		log(7, r2)
		r12 := fmt.Sprintf("%v%v", r1, sending.ByteOrder.Uint32(r2))
		log(8, r12)
		r12hash := hash.Sum([]byte(r12))
		log(9, r12hash)
		e := rsa.SignVer(r12hash[:], rsign, []byte(pk))
		if e != nil {
			panic("verify r2 sign error")
		}
		if err != nil {
			panic(err.Error())
		}
		sendRC4(conn)
	}
}

// 5
func sendRC4(conn net.Conn) {
	rc4s := getRC4Struct()
	err := send(conn, rc4s, false)
	if err != nil {
		panic(err.Error())
	}
	receiveRC4(conn)
}

// 8
func receiveRC4(conn net.Conn) {
	reader := bufio.NewReader(conn)
	data, _ := sending.ParseBuf(reader, sending.ServerSide)
	log(15, data)
	message, _ := sending.ParseMessage(bytes.NewReader(data.EncData))
	log(16, message)
	e := rsa.SignVer(data.Checksum[:], data.Sign, []byte(pk))
	if e != nil {
		panic("verify sign error")
	}
	if message.Head.Type == sending.RC4 {
		thatPubKey = new(big.Int).SetBytes(message.Body[0].Value)
		log(17, thatPubKey)
		privkey = diffHellman.GenPrivKey(thatPubKey, p, s)
		log(18, privkey)
		sendFile(conn)
	}
}

// 9
func sendFile(conn net.Conn) {
	var filePath string
	fmt.Println("请输入文件路径：")
	_, err := fmt.Scanf("%s", &filePath)
	if err != nil {
		fmt.Println(err.Error())
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Printf("数据（明文）：%s\n", data)
	fmt.Printf("数据（编码）：%x\n", data)
	key := privkey.Bytes()[:256]
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		fmt.Println(err.Error())
	}
	buf := data[:]
	cipher.XORKeyStream(buf, buf)

	fmt.Printf("数据（密文）：%x\n", buf)

	body := []sending.BodySlice{sending.NewBodySlice(buf)}
	sendBuf := sending.GetBuf(sending.SendMessage, body)

	sbuf := new(bytes.Buffer)
	dataHash := hash.Sum(sendBuf)
	err = binary.Write(sbuf, sending.ByteOrder, uint32(binary.Size(sendBuf)))
	err = binary.Write(sbuf, sending.ByteOrder, sendBuf)
	err = binary.Write(sbuf, sending.ByteOrder, dataHash)

	_, err = conn.Write(sbuf.Bytes())
	if err != nil {
		println("发送失败")
	}
}

func Handle(conn net.Conn) {
	sendHandshake(conn)
}
