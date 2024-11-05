package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	var tokenUpdateInterval int64
	var keychainService string
	var secret string
	flag.StringVar(&keychainService, "service", "", "Название сервиса в keychain, в котором хранится secret для OTP")
	flag.StringVar(&secret, "secret", "", "Секрет для генерации OTP (если не используется Keychain)")
	flag.Int64Var(&tokenUpdateInterval, "interval", 30, "Интервал обновления токена (по умолчанию 30 секунд)")
	flag.Parse()

	var otpSecret string
	var err error

	switch {
	case keychainService != "":
		otpSecret, err = getSecretFromKeychain(keychainService)
		if err != nil {
			log.Fatalf("Error retrieving secret from Keychain: %v", err)
		}
	case secret != "":
		otpSecret = secret
	default:
		fmt.Println("Usage: otp_getter --service=<keychain-service> or --secret=<your-secret-key>")
		os.Exit(1)
	}

	otp, err := generateTOTP(otpSecret, time.Now().Unix()/tokenUpdateInterval)
	if err != nil {
		log.Fatalf("Error generating OTP: %v", err)
	}

	fmt.Printf("%06d\n", otp)
}

// getSecretFromKeychain забирает секрет из keychain
func getSecretFromKeychain(service string) (string, error) {
	cmd := exec.Command("security", "find-generic-password", "-w", "-s", service)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

// generateTOTP формирует TOTP
func generateTOTP(secret string, timestamp int64) (int, error) {
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, err
	}

	// timestamp -> массив байт
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp))

	// key and timestamp hash
	hash := hmac.New(sha1.New, key)
	hash.Write(timeBytes)
	hmacHash := hash.Sum(nil)

	// последние 4 бита хэша используются для определения смещения
	const fourByteBitMask = 0x0F
	lastBit := hmacHash[len(hmacHash)-1]
	offset := lastBit & fourByteBitMask

	binaryCode := binary.BigEndian.Uint32(hmacHash[offset : offset+4])
	binaryCode = (binaryCode << 1) >> 1 // зануляется старший "знаковый" бит

	otp := int(binaryCode % 1000000)
	return otp, nil
}
