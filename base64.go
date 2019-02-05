package fincrypt

import (
	"encoding/base64"
	"errors"
)

// Base64Operation struct to be populated and provided by the caller
type Base64Operation struct {
	Direction int
	Input     string
}

// Calculate performs the coding operation as described in the Base64Operation variable, which should be populated by the caller
func (op Base64Operation) Calculate() (string, error) {
	// validate the input length
	if len(op.Input) == 0 {
		return "", errors.New("Input string has zero length")
	}

	var result string

	// caller specifies the direction
	if op.Direction == DirectionEncrypt {
		result = base64.StdEncoding.EncodeToString([]byte(op.Input))

		if len(result) == 0 {
			return "", errors.New("Failed to Base64 encode the given string")
		}
	} else {
		r, err := base64.StdEncoding.DecodeString(op.Input)

		if err != nil {
			return "", err
		}

		result = string(r)

		if len(result) == 0 {
			return "", errors.New("Failed to Base64 decode the given string")
		}
	}

	return result, nil
}
