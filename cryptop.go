// Package cryptop contains functions to perform cryptographic operations
package cryptop

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// operation mode
const (
	Encrypt = iota
	Decrypt
)

// Pack returns the packed representation of the given expanded hex string
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

// Expand returns the expanded representation of the given packed hex bytes
func Expand(input []byte) (string, error) {

	// validate the input
	if len(input) == 0 {
		return "", errors.New("ExpandToHex: Input string is zero length, exiting")
	}

	// encode!
	result := hex.EncodeToString(input)

	if len(result) == 0 {
		return "", errors.New("ExpandToHex: Failed to encode the given hex string, exiting")
	}

	return strings.ToUpper(result), nil
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
