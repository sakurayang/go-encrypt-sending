package sending

import (
	"crypto/rand"
	"math/big"
)

func GetNonce() int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(128))
	return n.Int64()
}