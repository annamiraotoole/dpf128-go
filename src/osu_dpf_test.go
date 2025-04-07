package dpf128

import (
	"bytes"
	"log"
	"math/rand"
	"testing"
)

func TestKeyGen(t *testing.T) {

	log.Printf("\n TestKeyGen... [only tests no-crashing, not functionality] \n")

	seed := rand.Uint64()

	const test_domain = uint64(10)

	points := []uint64{1}
	values := NewRandomElem()
	key0, key1, keySize := KeyGen(test_domain, points, values, seed)
	log.Printf("Generated Key0: %x...\n", key0[0:16])
	log.Printf("Generated Key1: %x...\n", key1[0:16])
	log.Printf("KeySize was: %d\n", keySize)
}

func TestExpand(t *testing.T) {

	log.Printf("\n TestExpand... [tests for correctness of KeyGen and Expand] \n")

	domain_powers := []uint64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
	for _, pow := range domain_powers {

		domain := uint64(1 << pow)

		log.Print("Testing domain ", domain, "= 2^", pow, "\n")

		iterations := 10 // tests per domain

		// make random points within that domain
		all_points := make([]uint64, iterations)
		for i := 0; i < iterations; i++ {
			all_points[i] = uint64(rand.Intn(int(domain)))
		}

		for run := 0; run < iterations; run++ {

			// make random seed
			seed := rand.Uint64()

			// make random values
			values := NewRandomElem()
			points := make([]uint64, num_points)
			points[0] = all_points[run]

			key0, key1, keySize := KeyGen(domain, points, values, seed)
			keyExp0 := Expand(left, domain, num_points, key0, keySize)
			keyExp1 := Expand(right, domain, num_points, key1, keySize)

			out := make([]byte, BLOCKSIZE)
			for b := uint64(0); b < domain; b++ {
				for j := 0; j < BLOCKSIZE; j++ {
					out[j] = keyExp0[BLOCKSIZE*int(b)+j] ^ keyExp1[BLOCKSIZE*int(b)+j]
					if b == points[0] {
						if out[j] != values.Data[j] {
							t.Errorf("Mismatch at domain block %d, byte %d: got %x, want %x", b, j, out[j], values.Data[BLOCKSIZE*int(b)+j])
						}
					} else {
						if out[j] != 0 {
							t.Errorf("Mismatch at domain block %d, byte %d: got %x, want 0", b, j, out[j])
						}
					}
				}
			}

		}
	}

}

func TestAPIR(t *testing.T) {

	log.Printf("\n Testing end-to-end osu-crypto CGO as an APIR protocol...[correctness of KeyGen, Expand, MultiplyDB] \n")

	domain_powers := []uint64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
	for _, pow := range domain_powers {

		domain := uint64(1 << pow)

		log.Print("Testing domain ", domain, "= 2^", pow, "\n")

		iterations := 10 // tests per domain

		// make random points within that domain
		all_points := make([]uint64, iterations)
		for i := 0; i < iterations; i++ {
			all_points[i] = uint64(rand.Intn(int(domain)))
		}

		// make random DB
		db := make([]byte, BLOCKSIZE*domain)
		for i := 0; i < len(db); i++ {
			db[i] = byte(rand.Intn(256))
		}

		for run := 0; run < iterations; run++ {

			seed := rand.Uint64()
			seedAuth := rand.Uint64()

			points := make([]uint64, num_points)
			points[0] = all_points[run]

			// AUTH PIR /////////////////////////////////////////////////

			valuesA := NewRandomElem()

			// make some keys
			key0A, key1A, keySizeA := KeyGen(domain, points, valuesA, seedAuth)
			keyExp0A := Expand(left, domain, num_points, key0A, keySizeA)
			keyExp1A := Expand(right, domain, num_points, key1A, keySizeA)

			// multiply the expanded keys by the database
			out0A := MultiplyDB(keyExp0A, db, int(domain))
			out1A := MultiplyDB(keyExp1A, db, int(domain))

			// XOR the results
			outA := NewFieldElem()
			XorDPF(out0A.Data, out1A.Data, outA.Data, BLOCKSIZE)

			// NORMAL PIR ////////////////////////////////////////////////

			// must be 1 in order to retrieve the original unchanged record
			valuesB := FieldElemOne()

			// make some keys
			key0B, key1B, keySizeB := KeyGen(domain, points, valuesB, seed)
			keyExp0B := Expand(left, domain, num_points, key0B, keySizeB)
			keyExp1B := Expand(right, domain, num_points, key1B, keySizeB)

			// multiply the expanded keys by the database
			out0B := MultiplyDB(keyExp0B, db, int(domain))
			out1B := MultiplyDB(keyExp1B, db, int(domain))

			// XOR the results
			outB := NewFieldElem()
			XorDPF(out0B.Data, out1B.Data, outB.Data, BLOCKSIZE)

			// MULTIPLY FOR AUTH CHECK ////////////////////////////////////

			// if normal * alpha = auth, we are good
			recon := FieldMul(outB, valuesA)

			if !bytes.Equal(recon.Data, outA.Data) {
				t.Fail()
			}

			// check that the retrieved record is correct
			if !bytes.Equal(outB.Data, db[BLOCKSIZE*int(points[0]):BLOCKSIZE*(int(points[0])+1)]) {
				t.Fail()
			}
		}
	}
}
