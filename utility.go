// Package cryptop contains functions to perform cryptographic operations
package cryptop

import (
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// cipher direction
const (
	DirectionEncrypt = iota
	DirectionDecrypt
)

// encryption modes
const (
	ModeECB = "ECB"
	ModeCBC = "CBC"
)

// Pack returns the packed representation of an expanded hex string which is provided
func Pack(input string) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New("Input string has zero length")
	}

	if len(input)%2 != 0 {
		return "", errors.New("Input string is an uneven length, use only full bytes")
	}

	upperInput := strings.ToUpper(input)

	match, err := regexp.MatchString("^[0-9A-F]+$", upperInput)

	if err != nil {
		return "", err
	}

	if match == false {
		return "", errors.New("Input string contains invalid characters, use hex only (0-9 A-F)")
	}

	// decode!
	result, err := hex.DecodeString(upperInput)

	if err != nil {
		return "", errors.New("Failed to decode the given hex")
	}

	return string(result), nil
}

// Expand returns the expanded representation of the packed hex bytes which are provided
func Expand(input []byte) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New("Input string has zero length")
	}

	// encode!
	result := hex.EncodeToString(input)

	if len(result) == 0 {
		return "", errors.New("Failed to encode the given hex string")
	}

	return strings.ToUpper(result), nil
}
