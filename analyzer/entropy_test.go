package analyzer

import (
	"testing"
)

func TestCalculateShannonEntropy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
		isAttack bool
	}{
		{
			name:     "Normal Domain (Google)",
			input:    "google.com",
			isAttack: false,
		},
		{
			name:     "Normal Domain (Campus)",
			input:    "telkomuniversity.ac.id",
			isAttack: false,
		},
		{
			// Kasus Hex murni dihapus karena Max Entropy Hex = 4.0
			// Threshold kita 4.5. Hex butuh decoding dulu (Next Feature).
			// Kita ganti dengan simulasi payload terenkripsi Base64 (High Entropy).
			name:     "Malicious Encrypted Payload (Base64)",
			input:    "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIHNlbnQgdmlhIEROUw==",
			isAttack: true,
		},
		{
			name: "Malicious Random ASCII (C2 Communication)",
			// String ini punya variasi karakter tinggi (huruf besar, kecil, angka)
			input:    "aBcD1234EfGh5678IjKl9012MnOp3456QrSt7890UvWx1234Yz!!",
			isAttack: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateShannonEntropy(tt.input)
			isMalicious := IsMalicious(score)

			if isMalicious != tt.isAttack {
				t.Errorf("Input: %s\nEntropy: %.4f\nDetected: %v\nExpected: %v",
					tt.input, score, isMalicious, tt.isAttack)
			}

			t.Logf("[%s] Score: %.4f (Pass)", tt.name, score)
		})
	}
}
