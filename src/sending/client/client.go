package client

import (
	"go-crypto-sending/src/encrypt/diffHellman"
	"go-crypto-sending/src/sending"
	"math"
	"math/big"
	"math/rand"
)

var (
	p, g, s, selfPubKey, thatPubKey, privkey *big.Int
)

// {e, n}
const pkE = 0x101
const pkN = 0xDC28132C5A78EBC5E61073E1FC0AEC6D649D9F2F8FA4A802B43E5A2490A4CFCD

func getR1Struct() []byte {
	r1 := uint32(rand.Intn(math.MaxUint16))
	body := []sending.BodySlice{sending.NewBodySlice(r1)}
	return sending.GetBuf(sending.HandShark, body)
}

func getRC4Struct() []byte {
	p, g, s, selfPubKey = diffHellman.GenKeys()
	body := []sending.BodySlice{
		sending.NewBodySlice(p),
		sending.NewBodySlice(g),
		sending.NewBodySlice(selfPubKey),
	}
	return sending.GetBuf(sending.RC4, body)
}
