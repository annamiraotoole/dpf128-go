package dpf128

/*
#cgo CXXFLAGS: -I/path/to/libOTe/test/include -std=c++20
#cgo LDFLAGS: -L/path/to/libOTe/test/lib -Wl,-rpath,/path/to/libOTe/test/lib -llibOTeShared
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "regular_dpf.h"
*/
import "C"
import (
	"log"
	"math"
	"math/rand"
)

const num_points = uint64(1)
const BLOCKSIZE = 16
const left = 0
const right = 1

type FieldElem struct {
	// 16 bytes (128 bits)
	Data []byte
}

func NewFieldElem() *FieldElem {
	return &FieldElem{
		Data: make([]byte, 16),
	}
}

// TODO improve this function
func NewRandomElem() *FieldElem {
	elem := NewFieldElem()
	for i := 0; i < len(elem.Data); i++ {
		elem.Data[i] = byte(rand.Intn(256))
	}
	return elem
}

func FieldElemOne() *FieldElem {
	elem := NewFieldElem()
	elem.Data[0] = 1
	return elem
}

// TODO make the seed full 128 bits instead of 64 bits
func KeyGen(domain uint64, points []uint64, values *FieldElem, seed uint64) ([]byte, []byte, uint64) {

	// If you are allocating this buffer on the go side, you can precompute the size of the buffer it will be
	// 16 + 16 * (numTrees * depth + numTrees) + numTrees * depth
	// where depth = log2Ceil(domain)

	numPoints := uint64(len(points))

	if len(values.Data) != 16*int(numPoints) {
		log.Println("Values length mismatch")
		return nil, nil, 0
	}

	// check that all points are in domain
	for _, point := range points {
		if point >= domain {
			log.Println("Point out of domain")
			return nil, nil, 0
		}
	}

	depth := uint64(math.Ceil(math.Log2(float64(domain))))

	expectedKeySize := 16 + 16*(num_points*depth+num_points) + num_points*depth

	key0 := make([]byte, expectedKeySize)
	key1 := make([]byte, expectedKeySize)

	reportedKeySize := make([]uint64, 1)

	C.keyGen(
		(C.uint64_t)(domain),
		(*C.uint64_t)(&points[0]),
		(*C.uint8_t)(&values.Data[0]),
		(C.uint64_t)(numPoints),
		(C.uint64_t)(seed),
		(*C.uint64_t)(&reportedKeySize[0]),
		(*C.uint8_t)(&key0[0]),
		(*C.uint8_t)(&key1[0]),
	)

	if reportedKeySize[0] != expectedKeySize {
		log.Println("Key size mismatch")
		log.Println("Expected:", expectedKeySize)
		log.Println("Got:", reportedKeySize[0])
	}

	return key0, key1, expectedKeySize
}

func Expand(partyIdx uint64, domain uint64, numPoints uint64, key []byte, keySize uint64) []byte {

	// Allocate memory for the output
	keyExp := make([]byte, 16*domain*numPoints)

	C.expand(
		(C.uint64_t)(partyIdx),
		(C.uint64_t)(domain),
		(C.uint64_t)(numPoints),
		(*C.uint8_t)(&key[0]),
		(C.uint64_t)(keySize),
		(*C.uint8_t)(&keyExp[0]))

	return keyExp
}

// Multiplies expanded key against the database, each chunk of 128 bits
// at a time. Uses GF128 multiplication from osu-crypto library
// length input is how many elements in the database, not how many bytes
// we would have len(DB) = length*16, but DB might be passed as a pointer
// to a larger buffer, so we can't rely on the len function
func MultiplyDB(keyExp []byte, DB []byte, length int) *FieldElem {

	// Allocate memory for the output
	out := NewFieldElem()

	// Call the function
	C.multiplyDB(
		(*C.uint8_t)(&keyExp[0]),
		(*C.uint8_t)(&DB[0]),
		(*C.uint8_t)(&out.Data[0]),
		C.int(length))

	return out
}

func XorDPF(a []byte, b []byte, out []byte, numBytes int) {

	// XOR the two byte slices
	for i := 0; i < numBytes; i++ {
		out[i] = a[i] ^ b[i]
	}

}

func FieldMul(x *FieldElem, y *FieldElem) *FieldElem {

	// Allocate memory for the output
	out := NewFieldElem()

	// Call the function
	C.gfmul(
		(*C.uint8_t)(&x.Data[0]),
		(*C.uint8_t)(&y.Data[0]),
		(*C.uint8_t)(&out.Data[0]))

	return out
}

func FieldAdd(x *FieldElem, y *FieldElem, out *FieldElem) {
	XorDPF(x.Data, y.Data, out.Data, BLOCKSIZE)
}
