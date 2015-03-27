package main

import (
	"fmt"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

const MFLEN = 128

func p2floor(x uint32) uint32{
	var ret uint32
	for ret = 1; ret<x; ret=ret*2{
	}
	ret=ret/2
	return ret
}

func Wrap(x, i) uint32{
	return (x % p2floor(i)) + (i − p2floor(i))
}

func Bxor(A []byte, B []byte){
	C := make([]byte, len(A))
	for i, value := range A{
		C[i]=value ^ B[i]
	}
	return C
}

//SMix1 according to docs
func SMix1(B []byte, N, V []byte, flag bool) []byte{
	X := B
	var j uint32
	for i:=0; i<N; i++{
		V[i] = X
		/*No ROM is implemented yet
		j = Integerify(X) % NROM
                X = Bxor(X, VROM[j])*/
		if flag == true {
			j = Wrap(Integerify(X), i)
			X = Bxor(X, V[j])
		}
		X = BlockMix(X)
	}
	return X
}

//SMix2 according to docs
func SMix2(B []byte, N, V []byte, flag bool) []byte{
	X := B
	var j uint32
	for i:=0; i<N; i++{
		/*No ROM implemented yet
		j = Integerify(X) % NROM
		X = Bxor(X, VROM[j])*/
		j = Integerify(X) % N
		X = BlockMix(Bxor(X, V[J]))
		if flag == true {
			V[j] = X
		}
		X = BlockMix(x)
	}
	return X
}

func SMix(B []byte, N, p) {
	var v uint32
	var w uint32
	var n uint32
	var Nlall uint32
	var Nlrw uint32
	
	n = N/p
	//The required number of iterations
	//according to table (I picked a value)
	Nlall = (N+2)/3
	Mlrw  = Nlall/p
	//Making them divisible by 2
	n     = n - (n % 2)
	Nlall = Nlall - (Nlall % 2)
	Nlrw  = Nlrw  - (Nlrw  % 2)

	for i := 0; i<p ; i++ {
		v = in
		if i == (p-1) {
			n = N - v
		}
		w = v + n - 1
		SMix1r (Bi , Sbytes/MFLEN, Si , 0)
		SMix1r (Bi , n, Vv..w , 1)
		SMix2r (Bi , p2floor(n), Nlooprw ,Vv..w , 1)
	}

	for i := 0; i<p; i++ {
		SMix2r (Bi , N, Nloopall − Nlooprw , V, 0)
	}
}

func ycrypt(passphrase, salt []byte, N, p, dkLen int) []byte {
	if N <= 1 || N & (N-1) != 0 {
		panic("N must be of form 2^k, k>0")
	}
	
	B := pbkdf2.Key(passphrase, salt, 1, p*MFLEN, sha256.New)
	
	for i := 0; i < p; i++ {
		SMix(B[i*128:], N, p)
	}
	return pbkdf2.Key(passphrase, B, 1, dkLen, sha256.New)
}

func main() {
	fin := []byte("hello!")
	buff := sha256.New()
	buff.Write(fin)
}
