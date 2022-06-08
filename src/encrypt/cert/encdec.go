package cert

import (
	"bytes"
	"encoding/gob"
	"math/big"
)

func Enc(msg string, key, e int) []byte {
	slice := make([]big.Int, 0)
	for _, v := range msg {
		slice = append(slice, *new(big.Int).Exp(
			big.NewInt(int64(v)),
			big.NewInt(int64(key)),
			big.NewInt(int64(e)),
		))
	}
	var buf bytes.Buffer
	_ = gob.NewEncoder(&buf).Encode(slice)
	return buf.Bytes()
}

func Dec(secMsg []byte, key, e int) string {
	slice := make([]rune, 0)
	buf := bytes.NewBuffer(secMsg)
	_ = gob.NewDecoder(buf).Decode(&slice)
	for _, v := range slice {
		slice = append(slice, rune(
			(*(new(big.Int))).Exp(
				big.NewInt(int64(v)),
				big.NewInt(int64(key)),
				big.NewInt(int64(e)),
			).Int64()),
		)
	}
	return string(slice)
}
