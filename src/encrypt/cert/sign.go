package cert

import (
	"bytes"
	"encoding/binary"
	"go-crypto-sending/src/encrypt/hash"
	"math/big"
)

func Sign(msg, key []byte, n int64) []byte {
	sign := hash.Sum(msg)
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, sign)

	_m := new(big.Int).SetBytes(buf.Bytes())
	_d := new(big.Int).SetBytes(key)
	_n := new(big.Int).SetInt64(n)

	t := new(big.Int).Exp(_m, _d, _n)
	return t.Bytes()
}

func Verify(msg, sign, key []byte, n int64) bool {
	_s := new(big.Int).SetBytes(sign)
	_e := new(big.Int).SetBytes(key)
	_n := new(big.Int).SetInt64(n)

	__s := new(big.Int).Exp(_s, _e, _n)
	__m := new(big.Int).SetBytes(msg)
	return __s.Cmp(__m) == 0
}
