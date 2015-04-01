package main

import (
	//"fmt"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

const MFLEN = 128

const S_BITS = 8
const S_P = 4
const S_ROUNDS = 6
const S_SIMD = 2

const S_N = 2

const S_SIZE1 = (1 << S_BITS)
const S_MASK = ((S_SIZE1 - 1) * S_SIMD * 8)
const S_SIZE_ALL = (S_N * S_SIZE1 * S_SIMD * 2)
const S_P_SIZE = (S_P * S_SIMD * 2)
const S_MIN_R = ((S_P * S_SIMD + 15) / 16)

// Simple functions
// ------

func p2floor(x uint32) uint32{
	var ret uint32
	for ret = 1; ret<x; ret=ret*2{
	}
	ret=ret/2
	return ret
}

func Wrap(x uint32, i uint32) uint32{
	return (x % p2floor(i)) + (i - p2floor(i))
}

func Bxor(A []uint32, B []uint32, sz int){
	for i:=0; i<sz; i++{
		A[i] = A[i] ^ B[i]
	}
}

func Bcopy(A []uint32, B []uint32, n int) {
	copy(A[:], B[:n])
}


//Base functions
//------

func H(B []uint32, S []uint32){

	//There's no way of making such pointer casts
	//Thus, we use the following formulas:
	//X[i][j][k]=B[2iS_SIMD+2j+k]
	//S0[i][j]=S[2i+j]
	//S1[i][j]=S[2i+j+S_SIZE1*S_SIMD]
	var i, j, k uint32

	var x, s0, s1 uint64
	
	var xl uint32
	var xh uint32

	//p0[i][j]=S[2i+j+(xl & S_MASK)]
	//p1[i][j]=S[2i+j+(xh & S_MASK)]
	
	for i = 0; i < S_ROUNDS; i++ {
		for j = 0; j < S_P; j++ {
			xl = B[2*j*S_SIMD]
			xh = B[2*j*S_SIMD+1]

			for k = 0; k < S_SIMD; k++ {
				s0 = (S[2*k+1+(xl & S_MASK)] << 32) + S[2*k+(xl & S_MASK)]
				s1 = (S[2*k+1+(xh & S_MASK)] << 32) + S[2*k+(xh & S_MASK)]
				xl = B[2*j*S_SIMD+2*k]
				xh = B[2*j*S_SIMD+2*k+1]

				x = uint64(xh * xl)
					
				x += s0
				x ^= s1

				B[2*j*S_SIMD+2*k] = uint32(x)
				B[2*j*S_SIMD+2*k+1]= uint32(x >> 32)
			}
		}
	}
}

func BMix(B []uint32, X []uint32, S []uint32, r int){
	var r1 int
	var r2 int
	var i int
	
	r1 = r * 128 / (S_P_SIZE * 4)
	Bcopy(X, B[((r1-1) * S_P_SIZE) :], S_P_SIZE)
	
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
func Integerify(B []uint32 , r int) uint64{
	return (B[(2*r-1)*16+13] << 32) + B[(2*r-1)*16]
}


//Main functions
// -----

//SMix1 according to docs
func SMix1(B []uint32 , r uint64, N uint64 , V []byte , flag bool) []byte{
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
		//todo: add blockmix salsa
		X = BlockMix(X)
	}
	return X
}

//SMix2 according to docs
func SMix2(B []byte, N, Nloop, V []byte, flag bool) []byte{
	X := B
	var j uint32
	for i:=0; i<Nloop; i++{
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

func SMix(B []byte, r int, N int, p int) {
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
		SMix1 (Bp, r, Np, Vp, 1)
		SMix2 (Bp, p2floor(n), Nlooprw ,V[v:w] , 1)
	}

	for i := 0; i<p; i++ {
		SMix(Bp, N, Nloopall - Nlooprw, V, 0)
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
