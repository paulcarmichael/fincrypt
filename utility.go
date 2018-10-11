// Package cryptop contains functions to perform cryptographic operations
package cryptop

import (
	"encoding/base64"
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
		return "", errors.New("Pack: Input string is zero length, exiting")
	}

	if len(input)%2 != 0 {
		return "", errors.New("Pack: Input string is an uneven length, exiting")
	}

	upperInput := strings.ToUpper(input)

	match, err := regexp.MatchString("^[0-9A-F]+$", upperInput)

	if err != nil {
		return "", err
	}

	if match == false {
		return "", errors.New("Pack: Input string contains invalid hex, exiting")
	}

	// decode!
	result, err := hex.DecodeString(upperInput)

	if err != nil {
		return "", errors.New("Pack: Failed to decode the given hex, exiting")
	}

	return string(result), nil
}

// Expand returns the expanded representation of the packed hex bytes which are provided
func Expand(input []byte) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New("Expand: Input string is zero length, exiting")
	}

	// encode!
	result := hex.EncodeToString(input)

	if len(result) == 0 {
		return "", errors.New("Expand: Failed to encode the given hex string, exiting")
	}

	return strings.ToUpper(result), nil
}

// EncodeB64 returns the base64 representation of the string which is provided
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
