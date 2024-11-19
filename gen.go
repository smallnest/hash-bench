package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	f, _ := os.Open("bench.log")
	scanner := bufio.NewScanner(f)

	var m = make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "BenchmarkHash/") {
			line := strings.TrimPrefix(line, "BenchmarkHash/")
			items := strings.Split(line, "\t")
			fields := strings.Split(strings.Trim(items[0], " "), "-")
			items[2] = strings.TrimSpace(items[2])
			took := strings.TrimSuffix(items[2], " ns/op")
			v := m[fields[0]]
			if v == "" {
				m[fields[0]] = took
			} else {
				m[fields[0]] = v + "," + took
			}

		}
	}

	fmt.Println(",32 bytes, 64 bytes, 128 bytes, 256 bytes, 512 bytes, 1024 bytes")
	fmt.Println("Sha1,", m["Sha1"])
	fmt.Println("Sha256,", m["Sha256"])
	fmt.Println("Sha256-simd,", m["Sha256SIMD"])
	fmt.Println("Sha512,", m["Sha512"])
	fmt.Println("MD5,", m["MD5"])
	fmt.Println("Fnv,", m["Fnv"])
	fmt.Println("CityHash,", m["CityHash"])
	fmt.Println("FarmHash,", m["FarmHash"])
	fmt.Println("Murmur3,", m["Murmur3"])
	fmt.Println("Highwayhash,", m["Highwayhash"])
	fmt.Println("XXHash64,", m["XXHash64"])
	fmt.Println("XXHash64_ASM,", m["XXHash64_ASM"])
	fmt.Println("MapHash64,", m["MapHash64"])
	fmt.Println("StdMapHash64,", m["StdMapHash64"])
	fmt.Println("ChibiHash64,", m["ChibiHash64"])
}
