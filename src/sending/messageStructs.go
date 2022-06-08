package sending

import (
	"bytes"
	"encoding/binary"
)

type MessageType int8

const (
	HandShark MessageType = iota
	RC4
	SendMessage
)

var ByteOrder = binary.BigEndian

type BodySlice struct {
	Length uint16
	Value  []byte
}

func NewBodySlice(value any) BodySlice {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, ByteOrder, value)
	return BodySlice{Length: uint16(binary.Size(buf)), Value: buf.Bytes()}
}

type MessageHead struct {
	Type       MessageType
	BodyLength uint32
}

type Message struct {
	Head MessageHead
	Body []BodySlice
}

func GetBuf(messageType MessageType, body []BodySlice) []byte {
	length := uint32(0)
	for _, b := range body {
		length += uint32(b.Length)
	}

	buf := new(bytes.Buffer)
	_ = binary.Write(buf, ByteOrder, messageType)
	_ = binary.Write(buf, ByteOrder, length)
	for _, b := range body {
		_ = binary.Write(buf, ByteOrder, b.Length)
		_ = binary.Write(buf, ByteOrder, b.Value)
	}
	return buf.Bytes()
}
