package fincrypt

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// CVVOperation struct to be populated by the caller
type CVVOperation struct {
	PAN         string
	Expiry      string
	ServiceCode string
	CVK         string
}

// CVVResult contains the calculated CVV variants
type CVVResult struct {
	CVV  string
	CVV2 string
	ICVV string
}

// Calculate generates the CVVs using data prepared in the CVVOperation variable
func (op CVVOperation) Calculate() (string, error) {

	// validate the lengths of the input
	if len(op.PAN) == 0 {
		return "", errors.New("PAN has zero length")
	}

	if len(op.Expiry) != 4 {
		return "", errors.New("Expiry must be 4 digits in the format YYMM")
	}

	if len(op.ServiceCode) != 3 {
		return "", errors.New("Service Code must be 3 digits")
	}

	if len(op.CVK) != 32 {
		return "", errors.New("CVK must be 16 bytes")
	}

	// prepare the required keys
	var err error

	op.CVK, err = Pack(op.CVK, InputNameCVK)

	if err != nil {
		return "", err
	}

	kl, err := des.NewCipher([]byte(op.CVK[:8]))

	if err != nil {
		return "", err
	}

	kr, err := des.NewCipher([]byte(op.CVK[8:]))

	if err != nil {
		return "", err
	}

	// calculate the CVV
	var result CVVResult

	result.CVV, err = op.calculateCVV(kl, kr)

	if err != nil {
		return "", err
	}

	// calculate the iCVV
	op.ServiceCode = "999"

	result.ICVV, err = op.calculateCVV(kl, kr)

	if err != nil {
		return "", err
	}

	// calculate the CVV2
	op.Expiry = op.Expiry[2:] + op.Expiry[:2]
	op.ServiceCode = "000"

	result.CVV2, err = op.calculateCVV(kl, kr)

	if err != nil {
		return "", err
	}

	// return the calculated CVVs
	resultBytes, err := json.Marshal(result)

	if err != nil {
		return "", errors.New("Failed to convert calculated CVVs to json")
	}

	return string(resultBytes), nil
}

// CalculateCVV calculates a CVV
func (op CVVOperation) calculateCVV(kl, kr cipher.Block) (string, error) {
	// prepare the concatenated input
	var b strings.Builder

	b.WriteString(op.PAN)
	b.WriteString(op.Expiry)
	b.WriteString(op.ServiceCode)

	input := b.String()
	iLen := len(input)

	if iLen < 32 {
		b.WriteString(strings.Repeat("0", 32-iLen))
		input = b.String()
	} else if iLen > 32 {
		input = input[:32]
	}

	// pack the input and data
	input, err := Pack(input, InputNameInput)

	if err != nil {
		return "", err
	}

	// prepare a buffer for the result
	blockSize := kl.BlockSize()

	r := make([]byte, blockSize)

	// encrypt the first block with kl
	kl.Encrypt(r, []byte(input[:blockSize]))

	// xor the result with second block
	r = XOR(r, []byte(input[blockSize:]))

	// encrypt the result with kl
	kl.Encrypt(r, r)

	// decrypt the result with kr
	kr.Decrypt(r, r)

	// encrypt the result with kl
	kl.Encrypt(r, r)

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

		if b.Len() >= 3 {
			break
		}
	}

	if b.Len() < 3 {
		for _, r := range chars {
			i, err := strconv.ParseInt(string(r), 16, 16)

			if err != nil {
				return "", err
			}

			b.WriteString(strconv.FormatInt(i%10, 10))

			if b.Len() >= 3 {
				break
			}
		}
	}

	return b.String()[:3], nil
}
