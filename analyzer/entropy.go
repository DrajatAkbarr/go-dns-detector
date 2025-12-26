package analyzer

import (
	"math"
)

// CalculateShannonEntropy menghitung tingkat keacakan string
// Menggunakan rumus H(X) = -sum(P(x) * log2(P(x)))
func CalculateShannonEntropy(data string) float64 {
	if data == "" {
		return 0
	}

	// Menghitung frekuensi setiap karakter
	frequencies := make(map[rune]float64)
	for _, char := range data {
		frequencies[char]++
	}

	var entropy float64
	length := float64(len(data))

	// Menghitung probabilitas dan entropi
	for _, count := range frequencies {
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// IsMalicious mengecek apakah entropy melebihi threshold
// Threshold 4.5 dipilih berdasarkan analisis anomali DNS Tunneling
func IsMalicious(entropy float64) bool {
	const Threshold = 4.5
	return entropy > Threshold
}
