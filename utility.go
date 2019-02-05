package fincrypt

import (
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// Direction specifies if an operation should encrypt or decrypt
type Direction int

// Specifies if an operation should encrypt or decrypt
const (
	DirectionEncrypt Direction = iota
	DirectionDecrypt
)

// Mode specifies if an operation should generate or validate
type Mode int

// Specifies if an operation should generate or validate
const (
	ModeGenerate Mode = iota
	ModeValidate
)

// CipherMode specifies if an operation should use ECB or CBC
type CipherMode string

// Specifies if an operation should use ECB or CBC
const (
	CipherModeECB CipherMode = "ECB"
	CipherModeCBC            = "CBC"
)

// input names
const (
	InputNameKey   = "Key"
	InputNameData  = "Data"
	InputNameIV    = "IV"
	InputNameInput = "Input"
	InputNameCVK   = "CVK"
)

// Operation interface is satisfied by all fincrypt tool structs
type Operation interface {
	Calculate() (string, error)
}

// Pack returns the packed representation of an expanded hex string
func Pack(input, name string) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New(name + " input has zero length")
	}

	if len(input)%2 != 0 {
		return "", errors.New(name + " input is an uneven length, use only full bytes")
	}

	upperInput := strings.ToUpper(input)

	match, err := regexp.MatchString("^[0-9A-F]+$", upperInput)

	if err != nil {
		return "", err
	}

	if match == false {
		return "", errors.New(name + " input contains invalid characters, use hex only (0-9 A-F)")
	}

	// decode!
	result, err := hex.DecodeString(upperInput)

	if err != nil {
		return "", errors.New("Failed to decode the given hex")
	}

	return string(result), nil
}

// Expand returns the expanded representation of the provided packed hex bytes
func Expand(input []byte) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New("Input has zero length")
	}

	// encode!
	result := hex.EncodeToString(input)

	if len(result) == 0 {
		return "", errors.New("Failed to encode the given hex")
	}

	return strings.ToUpper(result), nil
}

// XOR returns the XOR result of the two given byte slices, they are expected to have valid hexadecimal contents, equal lengths, and packed
func XOR(i1, i2 []byte) []byte {

	length := len(i1)
	r := make([]byte, length)

	for i := 0; i < length; i++ {
		r[i] = i1[i] ^ i2[i]
	}

	return r
}

// NumericOnly examines the given string and returns true if all bytes are numeric characters
func NumericOnly(s string) bool {

	match, err := regexp.MatchString("^[0-9]+$", s)

	if err != nil {
		return false
	}

	return match
}
