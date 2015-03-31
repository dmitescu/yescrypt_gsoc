package main

import (
	"fmt"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

const MFLEN = 128

const S_BITS = 8
const S_P_SIZE = ((S_P * S_SIMD + 15 ) / 16 )


// Simple functions
// ------

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

func Bxor(A []uint32, B []uint32, sz int){
	for i:=0; i<sz; i++{
		A[i]=value ^ B[i]
	}
}

func Bcopy(A []uint32, B []uint32, n int) {
	copy(A[:], B[:n])
}


//Base functions
//------

func H(B []uint32, S []uint32)
{
	
	uint32_t (*X)[S_SIMD][2] = (uint32_t (*)[S_SIMD][2])B
	const uint32_t (*S0)[2] = (const uint32_t (*)[2])S
	const uint32_t (*S1)[2] = S0 + S_SIZE1 * S_SIMD
	
	size_t i, j, k

	var x, s0, s1 uint64
	
	var xl uint32
	var xh uint32

	p0 = make(uint32, 2)
	p1 = make(uint32, 2)
	
	for i := 0; i < S_ROUNDS; i++ {
		for j := 0; j < S_P; j++ {
			xl = X[j][0][0]
			xh = X[j][0][1]

			p0 = S0 + (xl & S_MASK) / sizeof(*S0)
			p1 = S1 + (xh & S_MASK) / sizeof(*S1)

			for (k = 0; k < S_SIMD; k++) {
				s0 = (p0[k][1] << 32) + p0[k][0]
				s1 = (p1[k][1] << 32) + p1[k][0]

				xl = X[j][k][0]
				xh = X[j][k][1]

				x = uint64(xh * xl)
				x += s0
				x ^= s1

				X[j][k][0] = x
				X[j][k][1] = x >> 32
			}
		}
	}
}

func BMix(B []uint32, X []uint32, S []uint32, r int)
{
	var r1 int
	var r2 int
	var i int
	
	r1 = r * 128 / (S_P_SIZE * 4)
	Bcopy(X, B[((r1-1) * S_P_SIZE) :], S_P_SIZE]
	
	for i = 0; i < r1; i++ {
		Bxor(X, B[(i * S_P_SIZE):], S_P_SIZE)
		Hp(X, S);
		Bcopy(B[(i*S_P_SIZE):], X, S_P_SIZE)
	}

	i = (r1 - 1) * S_P_SIZE / 16
	r2 = r * 2

	H(B[(i * 16):])
	i++

	for i; i < r2; i++ {
		Bxor(B[(i * 16):16], B[(i-1)*16:], 16)
		H(B[i * 16])
	}
}

//Integerify
func Integerify(B []uint32 , r int) uint64
{
	return (B[(2*r-1)*16+13] << 32) + B[(2*r-1)*16]
}


//Main functions
// -----

//SMix1 according to docs
func SMix1(B []uint32 B, N uint64, V []byte, flag bool) []byte{
	X := B
	s := 32 * r
	
	var j uint32
	for i:=0; i<N; i++{
		Bcopy(V[i*s :], X, s)
		/*No ROM is implemented yet
		j = Integerify(X) % NROM
                X = Bxor(X, VROM[j])*/
		if flag == true {
			j = Wrap(Integerify(X, r), i)
			X = Bxor(X, V[j * s: ], s)
		}
		//to add blockmix salsa
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
		X = Bxor(X, VROM[j]) else*/
		j = Integerify(X, r) % (N-1)
		X = BlockMix(Bxor(X, V[j]))
		if flag == true {
			V[j] = X
		}
		X = BlockMix(x)
	}
	return X
}

func SMix(B []byte, r, N, p, t) {
	var v uint32
	var w uint32
	var n uint32
	var Nlall uint32
	var Nlrw uint32

	X = make([]uint32, 32*r)
	
	for i := 0; i < 32*r; i++ {
		X[i] = uint32(B[j]) | uint32(B[j+1])<<8 | uint32(B[j+2])<<16 | uint32(B[j+3])<<24
		j += 4
	}
	
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
		Bp = B[i*s:]
		Vp = V[Vchunk * s:]
		
		v = in
		if i == (p-1) {
			n = N - v
		}
		w = v + n - 1
		SMix1r (Bi , Sbytes/MFLEN, Si , 0)
		SMix1r (Bi , n, Vv..w , 1)
		SMix2r (Bi , p2floor(n), Nlooprw ,V[v:w] , 1)
	}

	for i := 0; i<p; i++ {
		SMix2r (Bi , N, Nloopall − Nlooprw , V, 0)
	}

	
	for _, v := range X[:32*r] {
		B[j+0] = byte(v >> 0)
		B[j+1] = byte(v >> 8)
		B[j+2] = byte(v >> 16)
		B[j+3] = byte(v >> 24)
		j += 4
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
