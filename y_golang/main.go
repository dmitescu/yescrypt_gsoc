package main

import (
	"fmt"
	"encoding/hex"
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

func p2floor(x uint64) uint64{
	var ret uint64
	ret = 1
	for ret <= x {
		ret=ret*2
	}
	ret=ret/2
	return ret
}

func Wrap(x uint64, i uint64) uint64{
	var r uint64
	r = p2floor(i)
	return (x % (r - 1)) + (i - r)
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

func R(a uint32, b uint32) uint32{
	return (((a) << (b)) | ((a) >> (32 - (b))))
}

func H(B []uint32){

	var x[16] uint32;
	var i int;

	/* Mimic SIMD shuffling */
	for i = 0; i < 16; i++{
	x[i * 5 % 16] = B[i]
	}
	
	for i = 0; i < 8; i += 2 {
		/* Operate on columns */
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9)
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18)

		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9)
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18)

		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9)
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18)

		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9)
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18)

		/* Operate on rows */
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9)
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18)

		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9)
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18)

		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9)
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18)

		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9)
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18)
	}

	for i = 0; i < 16; i++ {
		B[i] += x[i * 5 % 16];
	}
}

func Hp(B []uint32, S []uint32){

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
				s0 = (uint64(S[2*k+1+(xl & S_MASK)]) << 32) + uint64(S[2*k+(xl & S_MASK)])
				s1 = (uint64(S[2*k+1+(xh & S_MASK)]) << 32) + uint64(S[2*k+(xh & S_MASK)])
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

	for j:=i; j < r2; j++ {
		Bxor(B[(j * 16):16], B[(j-1)*16:], 16)
		H(B[j * 16 :])
	}
}

//Integerify
func Integerify(B []uint32 , r int) uint64{
	return (uint64(B[(2*r-1)*16+13]) << 32) + uint64(B[(2*r-1)*16])
}


//Main functions
// -----

//SMix1 according to docs
func SMix1(B []byte , r int, N uint64 , V []uint32, X []uint32, flag bool){

	for k := 0; k < 2*r; k++{
		for i := 0; i < 16; i++{
			tmp := uint32(B[k*16+(i*5 % 16)+0])
			tmp += uint32(B[k*16+(i*5 % 16)+1]) << 8
			tmp += uint32(B[k*16+(i*5 % 16)+2]) << 16
			tmp += uint32(B[k*16+(i*5 % 16)+3]) << 24
			X[k*16+i] = tmp
		}
	}
	
	var s uint64
	var j uint64
	var i uint64

	s = 32 * uint64(r)

	for i = 0; i < N; i++{
	 	Bcopy(V[i*uint64(s) :], X, int(s))
		/*No ROM is implemented yet
		j = Integerify(X) % NROM
                X = Bxor(X, VROM[j])*/
		if flag == true && i>1 {
			j = Wrap(Integerify(X, r), i)
			Bxor(X, V[j * s: ], int(s))
		}
		H(X)
	}

	for k := 0; k < 2*r; k++{
		for i := 0; i < 16; i++{
			B[k*16+(i*5 % 16)+0] = byte(X[k*16+i]) & 0xff
			B[k*16+(i*5 % 16)+1] = byte(X[k*16+i] >>  8) & 0xff 
			B[k*16+(i*5 % 16)+2] = byte(X[k*16+i] >> 16) & 0xff
			B[k*16+(i*5 % 16)+3] = byte(X[k*16+i] >> 24) & 0xff
		}
	}

	
}

//SMix2 according to docs
func SMix2(B []byte, r int, N uint64, Nloop uint64, V []uint32, X []uint32, flag bool){
	
	for k := 0; k < 2*r; k++{
		for i := 0; i < 16; i++{
			tmp := uint32(B[k*16+(i*5 % 16)+0])
			tmp += uint32(B[k*16+(i*5 % 16)+1]) << 8
			tmp += uint32(B[k*16+(i*5 % 16)+2]) << 16
			tmp += uint32(B[k*16+(i*5 % 16)+3]) << 24
			X[k*16+i] = tmp
		}
	}
	
	var j uint64
	
	for i:=0; i<int(Nloop); i++{
		/*No ROM implemented yet
		j = Integerify(X) % NROM
		X = Bxor(X, VROM[j]) else*/
		j = Integerify(X, r) % (N-1)
		Bxor(X, V[j*32*uint64(r):], 32*r)
		if flag == true {
			Bcopy(V[32*uint64(r)*j:],X,32*r)
		}
		H(X)
	}
	
	for k := 0; k < 2*r; k++{
		for i := 0; i < 16; i++{
			B[k*16+(i*5 % 16)+0] = byte(X[k*16+i]) & 0xff
			B[k*16+(i*5 % 16)+1] = byte(X[k*16+i] >>  8) & 0xff 
			B[k*16+(i*5 % 16)+2] = byte(X[k*16+i] >> 16) & 0xff
			B[k*16+(i*5 % 16)+3] = byte(X[k*16+i] >> 24) & 0xff
		}
	}

}

func SMix(B []byte, r int, N uint64, p int, V []uint32, X []uint32) {

	var n uint64
	
	var Nlall  uint64
	var Nlrw   uint64
	var Vchunk uint64
	var Nchunk uint64
	
	Vchunk=0
	
	Nchunk = N/uint64(p)
	Nlall = Nchunk
	
	//The required number of iterations
	//according to table (I picked a value)
	Nlall = (N+2)/3
	Nlrw  = Nlall/uint64(p)
	
	//Making them divisible by 2
	Nchunk = Nchunk - (Nchunk % 2)
	Nlall  = Nlall - (Nlall % 2)
	Nlrw   = Nlrw  - (Nlrw  % 2)

	for i := 0; i<p ; i++ {
		Bp := B[i*32*r:]
		Vp := V[Vchunk * 32*uint64(r):]
		
		if i < (p-1) {
			n = N - Vchunk
		}else {
			n = Nchunk
		}
		
		SMix1 (Bp, r, n, Vp, X, true)
		SMix2 (Bp, r, p2floor(n), Nlrw ,Vp, X, true)
	}

	for i := 0; i<p; i++ {
		Bp := B[i * 32 * r:]
		SMix2(Bp, r, N, Nlall - Nlrw, V, X, false)
	}

	
}

func ycrypt(passphrase []byte, salt []byte, N uint64, r int, p int) []byte {
	if N <= 1 || N & (N-1) != 0 {
		panic("N must be of form 2^k, k>0")
	}

	B := pbkdf2.Key(passphrase, salt, 1, 128*r*p, sha256.New)
	V := make([]uint32, 128*r*int(N))
	X := make([]uint32, 256*r)
	
	for i := 0; i < p; i++ {
		SMix(B[i*r*32:], r, N, p, V, X)
	}
	
	return pbkdf2.Key(passphrase, B, 1, len(B), sha256.New)
}

func main() {
	newpass := []byte("password")
	newsalt := []byte("NaCl")
	pass := ycrypt(newpass, newsalt, 1024, 8, 16)
	fmt.Println(hex.EncodeToString(pass))
}
