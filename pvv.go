package fincrypt

import (
	"crypto/des"
	"errors"
	"strconv"
	"strings"
)

// PVVOperation struct to be populated by the caller
type PVVOperation struct {
	PAN  string
	PVKI string
	PIN  string
	PVK  string
}

// Calculate generates a PVV using input data populated in the PVVOperation variable
func (op PVVOperation) Calculate() (string, error) {

	// validate the lengths of the input elements
	if len(op.PAN) < 12 {
		return "", errors.New("PAN must be at least 12 digits in length")
	}

	if len(op.PVKI) != 1 {
		return "", errors.New("PVKI must be 1 digit in length")
	}

	if len(op.PIN) != 4 {
		return "", errors.New("PIN must be 4 digits in length")
	}

	if len(op.PVK) != 32 &&
		len(op.PVK) != 48 {
		return "", errors.New("PVK must be 32 or 48 digits in length")
	}

	// prepare the concatenated input
	var b strings.Builder

	// strip the luhn digit from the PAN and take the 11 right most digits
	op.PAN = op.PAN[:len(op.PAN)-1]
	b.WriteString(op.PAN[len(op.PAN)-11:])
	b.WriteString(op.PVKI)
	b.WriteString(op.PIN)

	if b.Len() != 16 {
		return "", errors.New("PVV input is not 16 digits, check input lengths")
	}

	// pack the input data and the PVK
	input, err := Pack(b.String(), InputNameInput)

	if err != nil {
		return "", err
	}

	op.PVK, err = Pack(op.PVK, InputNameKey)

	if err != nil {
		return "", err
	}

	// prepare the key
	if len(op.PVK) == 16 {
		op.PVK += op.PVK[:8]
	}

	k, err := des.NewTripleDESCipher([]byte(op.PVK))

	if err != nil {
		return "", err
	}

	// prepare a buffer for the result
	blockSize := k.BlockSize()

	r := make([]byte, blockSize)

	// encrypt the data block with the key
	k.Encrypt(r, []byte(input))

	// extract the numeric digits from the result
	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	b.Reset()
	var chars string

	for _, r := range result {
		if NumericOnly(string(r)) == true {
			b.WriteRune(r)
		} else {
			chars += string(r)
		}

		if b.Len() >= 4 {
			break
		}
	}

	if b.Len() < 4 {
		for _, r := range chars {
			i, err := strconv.ParseInt(string(r), 16, 16)

			if err != nil {
				return "", err
			}

			b.WriteString(strconv.FormatInt(i%10, 10))

			if b.Len() >= 4 {
				break
			}
		}
	}

	return b.String()[:4], nil
}
