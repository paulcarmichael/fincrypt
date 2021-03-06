package fincrypt

import (
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// Operation interface is satisfied by all fincrypt tool structs
type Operation interface {
	Calculate() (string, error)
}

// Direction specifies if an operation should encrypt or decrypt
type Direction int

// Direction enum specifies if an operation should encrypt or decrypt
const (
	DirectionEncrypt Direction = iota
	DirectionDecrypt
)

// Mode specifies if an operation should generate or validate
type Mode int

// Mode enum specifies if an operation should generate or validate
const (
	ModeGenerate Mode = iota
	ModeValidate
)

// CipherMode specifies a cipher chaining mode
type CipherMode string

// CipherMode specifies a cipher chaining mode
const (
	CipherModeECB CipherMode = "ECB"
	CipherModeCBC            = "CBC"
)

// HashMode specifies the mode of a hash function
type HashMode string

// HashMode modes of of hash function
const (
	HashModeSHA1   HashMode = "SHA-1"
	HashModeSHA224          = "SHA-224"
	HashModeSHA256          = "SHA-256"
	HashModeSHA384          = "SHA-384"
	HashModeSHA512          = "SHA-512"
	HashModeMD4             = "MD4"
	HashModeMD5             = "MD5"
)

// InputName specifies input element names for error reporting
type InputName string

// InputName enum specifies input element names for error reporting
const (
	InputNameCVK             InputName = "CVK"
	InputNameData                      = "Data"
	InputNameInput                     = "Input"
	InputNameInput1                    = "Input 1"
	InputNameInput2                    = "Input 2"
	InputNameIV                        = "IV"
	InputNameKey                       = "Key"
	InputNameMasterKey                 = "Master Key"
	InputNameModulus                   = "Modulus"
	InputNamePPK                       = "PPK"
	InputNamePrivateExponent           = "Private Exponent"
	InputNamePublicExponent            = "Public Exponent"
	InputNamePVK                       = "PVK"
	InputNameTag                       = "Tag"
	InputNameVariant                   = "Variant"
)

// Pack returns the packed representation of an expanded hex string
func Pack(input string, name InputName) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New(string(name) + " has zero length")
	}

	if len(input)%2 != 0 {
		return "", errors.New(string(name) + " is an uneven length, use only full bytes")
	}

	upperInput := strings.ToUpper(input)

	match, err := regexp.MatchString("^[0-9A-F]+$", upperInput)

	if err != nil {
		return "", err
	}

	if match == false {
		return "", errors.New(string(name) + " contains invalid characters, use hex digits only (0-9 A-F)")
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
