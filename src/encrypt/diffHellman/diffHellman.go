package diffHellman

import (
	//"bufio"
	"crypto/rand"
	"math/big"
)

// GenKeys return pub_p, pub_g, pri_s
func GenKeys() (*big.Int, *big.Int, *big.Int, *big.Int) {
	// rfc3526, 2
	p, _ := new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	g := big.NewInt(2)
	s, pubKey := GenPubKeyUseNumbers(p, g)

	return p, g, s, pubKey
}

// GenPubKeyUseNumbers use public number gen a secret number
func GenPubKeyUseNumbers(p *big.Int, g *big.Int) (*big.Int, *big.Int) {
	s, _ := rand.Int(rand.Reader, p)
	pubKey := new(big.Int).Exp(g, s, p)
	return s, pubKey
}

func GenPrivKey(pubKey, p, s *big.Int) *big.Int {
	return new(big.Int).Exp(pubKey, s, p)
}
