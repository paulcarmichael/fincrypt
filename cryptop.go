// Package cryptop contains functions to perform cryptographic operations
package cryptop

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// enum equivalent to request an operation mode
const (
	Encrypt = iota
	Decrypt
)

// PackFromHex returns the packed representation of the given expanded hex string
func PackFromHex(input string) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New("PackFromHex: Input string is zero length, exiting")
	}

	if len(input)%2 != 0 {
		return "", errors.New("PackFromHex: Input string is an uneven length, exiting")
	}

	upperInput := strings.ToUpper(input)

	match, err := regexp.MatchString("^[0-9A-F]+$", upperInput)

	if err != nil {
		return "", err
	}

	if match == false {
		return "", errors.New("PackFromHex: Input string contains invalid hex, exiting")
	}

	// decode!
	result, err := hex.DecodeString(upperInput)

	if err != nil {
		return "", errors.New("PackFromHex: Failed to decode the given hex, exiting")
	}

	return string(result), nil
}

// ExpandToHex returns the expanded hex representation of the given string
func ExpandToHex(input string) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New("ExpandToHex: Input string is zero length, exiting")
	}

	// encode!
	result := hex.EncodeToString([]byte(input))

	if len(result) == 0 {
		return "", errors.New("ExpandToHex: Failed to encode the given hex string, exiting")
	}

	return strings.ToUpper(result), nil
}

// XOR from tiny acorns do mighty oaks grow
func XOR(s1, s2 string) (string, error) {

	// validate the input lengths
	length := len(s1)

	if length != len(s2) {
		return "", errors.New("XOR: Given inputs are different lengths, exiting")
	}

	// xor!
	r := make([]byte, length)

	for i := 0; i < length; i++ {
		r[i] = s1[i] ^ s2[i]
	}

	return string(r), nil
}

// EncodeB64 returns the base64 representation of the given string
func EncodeB64(input string) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New("EncodeB64: Input string is zero length, exiting")
	}

	// encode!
	result := base64.StdEncoding.EncodeToString([]byte(input))

	if len(result) == 0 {
		return "", errors.New("EncodeB64: Failed to encode the given string, exiting")
	}

	return result, nil
}

// AES_CBC the data should be padded by the caller
func AES_CBC(key, data, iv string, mode int) (string, error) {

	// validate the key length
	// 16 - AES-128
	// 32 - AES-256
	keyLength := len(key)

	if keyLength == 16 ||
		keyLength == 32 {
		//happy
	} else {
		return "", errors.New("AES_CBC: Key must be 16/32 bytes")
	}

	// validate the data - it must be a multiple of the blocksize
	dataLength := len(data)

	if dataLength%aes.BlockSize != 0 {
		return "", errors.New("AES_CBC: Data must be padded to a multiple of 16")
	}

	// validate the iv length
	ivLength := len(iv)

	if ivLength != 16 {
		return "", errors.New("AES_CBC: IV must be 16 bytes")
	}

	// prepare the key
	keyBytes := []byte(key)

	block, err := aes.NewCipher(keyBytes)

	if err != nil {
		return "", err
	}

	// prepare a buffer for the result
	result := make([]byte, dataLength)

	// the caller specifies the operation mode
	var blockMode cipher.BlockMode

	if mode == Encrypt {
		blockMode = cipher.NewCBCEncrypter(block, []byte(iv))
	} else {
		blockMode = cipher.NewCBCDecrypter(block, []byte(iv))
	}

	// godspeed
	blockMode.CryptBlocks(result, []byte(data))

	return string(result), nil
}
