package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// --- KONFIGURASI ---
const (
	device      = "en0" // PENTING: Karena Anda pakai Mac, ini WAJIB en0
	snapshotLen = 1024
	promiscuous = true
	timeout     = 30 * time.Second
)

func main() {
	// 1. MEMBUKA HANDLE JARINGAN (Ini yang tadi hilang!)
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// 2. SETUP FILTER REGEX (Deteksi Pola Hexadecimal)
	// Mencari string kombinasi angka 0-9 dan huruf a-f minimal 10 karakter
	hexPattern := regexp.MustCompile(`^[a-fA-F0-9]{10,}$`)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// TAMPILAN AWAL
	fmt.Println("--------------------------------------------------")
	fmt.Println("[*] SILENT-SENTRY ACTIVE (BEHAVIORAL MODE)")
	fmt.Println("[*] Monitoring Interface:", device)
	fmt.Println("[*] Detecting: Suspected DNS Exfiltration Patterns")
	fmt.Println("--------------------------------------------------")

	// 3. LOOPING PEMROSESAN PAKET
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)

			// Cek apakah ini Query (Pertanyaan) dan bukan kosong
			if !dns.QR && len(dns.Questions) > 0 {
				qName := string(dns.Questions[0].Name)

				// --- LOGIKA CERDAS (BEHAVIORAL) ---

				// Pecah domain berdasarkan titik (misal: payload.google.test)
				parts := strings.Split(qName, ".")

				if len(parts) > 0 {
					subdomain := parts[0]

					// Cek apakah subdomainnya polanya Hexadecimal aneh?
					if hexPattern.MatchString(subdomain) {

						// ALARM MERAH!
						fmt.Printf("\033[31m[!!!] ALERT DETECTED [!!!]\033[0m\n")
						fmt.Printf("Time   : %s\n", time.Now().Format("15:04:05"))
						fmt.Printf("Target : %s\n", qName)
						fmt.Printf("Payload: %s (Suspicious Hex)\n", subdomain)
						fmt.Println("--------------------------------------------------")
					}
				}
			}
		}
	}
}
