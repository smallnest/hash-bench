package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"testing"

	"bitbucket.org/creachadair/cityhash"
	xxhashasm "github.com/cespare/xxhash"
	farmhash "github.com/leemcloughlin/gofarmhash"
	"github.com/minio/highwayhash"
	"github.com/pierrec/xxHash/xxHash64"
	"github.com/spaolacci/murmur3"
)

var n int64
var testBytes []byte

func BenchmarkHash(b *testing.B) {
	sizes := []int64{32, 64, 128, 256, 512, 1024}
	for _, n = range sizes {
		testBytes = make([]byte, n)
		readN, err := rand.Read(testBytes)
		if readN != int(n) {
			panic(fmt.Sprintf("expect %d but got %d", n, readN))
		}
		if err != nil {
			panic(err)
		}

		b.Run(fmt.Sprintf("Sha1-%d", n), benchmarkSha1)
		b.Run(fmt.Sprintf("Sha256-%d", n), BenchmarkSha256)
		b.Run(fmt.Sprintf("Sha512-%d", n), BenchmarkSha512)
		b.Run(fmt.Sprintf("MD5-%d", n), BenchmarkMD5)
		b.Run(fmt.Sprintf("Fnv-%d", n), BenchmarkFnv)
		b.Run(fmt.Sprintf("CityHash-%d", n), BenchmarkCityhash)
		b.Run(fmt.Sprintf("FarmHash-%d", n), BenchmarkFarmhash)
		b.Run(fmt.Sprintf("Murmur3-%d", n), BenchmarkMurmur3)
		b.Run(fmt.Sprintf("Highwayhash-%d", n), BenchmarkHighwayhash)
		b.Run(fmt.Sprintf("XXHash64-%d", n), BenchmarkXXHash64)
		b.Run(fmt.Sprintf("XXHash64_ASM-%d", n), BenchmarkXXHash64_ASM)
		fmt.Println()
	}

}

func benchmarkSha1(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x := sha1.New()
		x.Write(testBytes)
		_ = x.Sum(nil)
	}
}
func BenchmarkSha256(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x := sha256.New()
		x.Write(testBytes)
		_ = x.Sum(nil)
	}
}

func BenchmarkSha512(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x := sha512.New()
		x.Write(testBytes)
		_ = x.Sum(nil)
	}
}

func BenchmarkMD5(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x := md5.New()
		x.Write(testBytes)
		_ = x.Sum(nil)
	}
}
func BenchmarkFnv(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x := fnv.New64()
		x.Write(testBytes)
		_ = x.Sum(nil)
	}
}

func BenchmarkCityhash(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = cityhash.Hash64WithSeed(testBytes, 0xCAFE)
	}
}

func BenchmarkFarmhash(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = farmhash.Hash64WithSeed(testBytes, 0xCAFE)
	}
}

func BenchmarkMurmur3(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x := murmur3.New64()
		x.Write(testBytes)
		_ = x.Sum(nil)
	}
}
func BenchmarkHighwayhash(b *testing.B) {
	key, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000") // use your own key here

	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x, _ := highwayhash.New64(key)
		x.Write(testBytes)
		_ = x.Sum(nil)
	}
}

func BenchmarkXXHash64(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x := xxHash64.New(0xCAFE)
		x.Write(testBytes)
		_ = x.Sum64()
	}
}

func BenchmarkXXHash64_ASM(b *testing.B) {
	b.SetBytes(n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x := xxhashasm.New()
		x.Write(testBytes)
		_ = x.Sum64()
	}
}
