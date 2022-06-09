package sending

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"go-crypto-sending/src/encrypt/hash"
	"io"
)

type MessageType int8

const (
	HandShake MessageType = iota
	RC4
	SendMessage
)

type Direction int8

const (
	ServerSide Direction = iota
	ClientSide
)

var ByteOrder = binary.BigEndian

type BodySlice struct {
	Length uint32
	Value  []byte
}

func NewBodySlice(value any) BodySlice {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, ByteOrder, value)
	return BodySlice{Length: uint32(binary.Size(buf.Bytes())), Value: buf.Bytes()}
}

type MessageHead struct {
	Type       MessageType
	BodyLength uint32
}

type Message struct {
	Head MessageHead
	Body []BodySlice
}

type EncMessage struct {
	DataLength uint32
	EncData    []byte
	// ChecksumLength uint32
	Checksum [16]byte
	Sign     []byte
}

func (e EncMessage) String() string {
	return fmt.Sprintf("data length: %d, enc data: %v, checksum: %x, sign: %x", e.DataLength, e.EncData, e.Checksum, e.Sign)
}

func GetBuf(messageType MessageType, body []BodySlice) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, ByteOrder, messageType)
	_ = binary.Write(buf, ByteOrder, uint32(len(body)))
	for _, b := range body {
		_ = binary.Write(buf, ByteOrder, b.Length)
		_ = binary.Write(buf, ByteOrder, b.Value)
	}
	return buf.Bytes()
}

func ParseBuf(reader *bufio.Reader, from Direction) (*EncMessage, error) {
	var err error = nil
	encMessage := EncMessage{}

	err = binary.Read(reader, ByteOrder, &encMessage.DataLength)
	encData := make([]byte, encMessage.DataLength)
	_, err = io.ReadFull(reader, encData)
	encMessage.EncData = encData

	err = binary.Read(reader, ByteOrder, &encMessage.Checksum)

	if from == ServerSide {
		signSize := reader.Buffered() /*- binary.Size(encMessage.Checksum) - int(encMessage.DataLength)*/
		s := make([]byte, signSize)
		_, err = io.ReadFull(reader, s)
		encMessage.Sign = s
	}

	selfChecksum := hash.Sum(encMessage.EncData)
	if uint32(binary.Size(encMessage.EncData)) != encMessage.DataLength || selfChecksum != encMessage.Checksum {
		return nil, errors.New("message error")
	}

	return &encMessage, err
}

func ParseMessage(reader *bytes.Reader) (*Message, error) {
	var err error = nil
	message := Message{}
	head := MessageHead{}
	err = binary.Read(reader, ByteOrder, &head.Type)
	err = binary.Read(reader, ByteOrder, &head.BodyLength)
	var body []BodySlice
	for i := uint32(0); i < head.BodyLength; i++ {
		b := BodySlice{}
		err = binary.Read(reader, ByteOrder, &b.Length)
		value := make([]byte, b.Length)
		_, err = io.ReadFull(reader, value)
		b.Value = value
		body = append(body, b)
	}
	message.Head = head
	message.Body = body
	return &message, err
}
