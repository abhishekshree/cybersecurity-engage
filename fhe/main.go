package main

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var (
	ErrBigMsg    = errors.New("message size greater than public key size")
	ErrBigCipher = errors.New("cipher size greater than public key size")
)

var one = big.NewInt(1)

type Num = big.Int

type PrivateKey struct {
	L *Num
	U *Num
	PublicKey
}

type PublicKey struct {
	N        *Num
	G        *Num
	NSquared *Num
}

func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	n := new(Num).Mul(p, q)
	g := new(Num).Add(n, one)
	nsquare := new(Num).Mul(n, n)

	// l = phi(n) = (p-1) * (q-1)
	l := new(Num).Mul(
		new(Num).Sub(p, one),
		new(Num).Sub(q, one),
	)

	// u = l^(-1) mod n
	u := new(Num).ModInverse(l, n)

	return &PrivateKey{
		L: l,
		U: u,
		PublicKey: PublicKey{
			N:        n,
			G:        g,
			NSquared: nsquare,
		},
	}, nil
}

func Encrypt(pub *PublicKey, plainText []byte) ([]byte, error) {
	r, err := rand.Prime(rand.Reader, pub.N.BitLen())
	if err != nil {
		return nil, err
	}

	m := new(Num).SetBytes(plainText)
	if m.Cmp(pub.NSquared) == 1 {
		return nil, ErrBigMsg
	}

	// enc = g^m * r^n mod n^2
	enc := new(Num).Mod(
		new(Num).Mul(
			new(Num).Exp(pub.G, m, pub.NSquared),
			new(Num).Exp(r, pub.N, pub.NSquared),
		),
		pub.NSquared,
	)
	return enc.Bytes(), nil
}

func Decrypt(priv *PrivateKey, cipherText []byte) ([]byte, error) {
	c := new(Num).SetBytes(cipherText)
	if c.Cmp(priv.NSquared) == 1 {
		return nil, ErrBigCipher

	}

	// a = c^l mod N^2
	// l(a) = (a - 1) / n
	l := new(Num).Div(
		new(Num).Sub(new(Num).Exp(c, priv.L, priv.NSquared), one),
		priv.N,
	)

	// m = L(c^l mod n^2) * u mod n
	m := new(Num).Mod(
		new(Num).Mul(l, priv.U),
		priv.N,
	)
	return m.Bytes(), nil
}

func HommorphicAddition(pub *PublicKey, ciphers ...[]byte) ([]byte, error) {
	C := one

	for i := 0; i < len(ciphers); i++ {
		cipher := new(Num).SetBytes(ciphers[i])
		if cipher.Cmp(pub.NSquared) == 1 {
			return nil, ErrBigCipher
		}

		// C = c1*c2*c3...cn mod N
		C = new(Num).Mod(
			new(Num).Mul(C, cipher),
			pub.NSquared,
		)
	}
	return C.Bytes(), nil
}
