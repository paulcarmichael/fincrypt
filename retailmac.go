package fincrypt

import (
	"crypto/des"
	"errors"
	"strings"
)

// RetailMACPaddingMode specifies the type of padding applied to the data
type RetailMACPaddingMode string

// RetailMAC padding modes
const (
	RetailMACPaddingModeNone    RetailMACPaddingMode = "NONE"
	RetailMACPaddingModeMethod1                      = "M1"
	RetailMACPaddingModeMethod2                      = "M2"
)

// RetailMACOperation struct to be populated by the caller
type RetailMACOperation struct {
	Key     string
	Data    string
	Padding RetailMACPaddingMode
}

// Calculate results in the creation of a Retail MAC
func (op RetailMACOperation) Calculate() (string, error) {
	// pack the key and data
	var err error

	op.Key, err = Pack(op.Key, InputNameKey)

	if err != nil {
		return "", err
	}

	op.Data, err = Pack(op.Data, InputNameData)

	if err != nil {
		return "", err
	}

	// validate the key length
	if len(op.Key) != 16 {
		return "", errors.New("Key must be 16 bytes")
	}

	// prepare the required keys
	kl, err := des.NewCipher([]byte(op.Key[:8]))

	if err != nil {
		return "", err
	}

	kr, err := des.NewCipher([]byte(op.Key[8:]))

	if err != nil {
		return "", err
	}

	blockSize := kl.BlockSize()

	// pad the data accordingly
	if op.Padding == RetailMACPaddingModeMethod1 ||
		op.Padding == RetailMACPaddingModeMethod2 {

		var b strings.Builder
		b.WriteString(op.Data)

		if op.Padding == RetailMACPaddingModeMethod1 {
			if b.Len()%blockSize != 0 {
				b.WriteByte(0x00)
			}
		} else {
			b.WriteByte(0x80)
		}

		for b.Len()%blockSize != 0 {
			b.WriteByte(0x00)
		}

		op.Data = b.String()
	} else {
		if len(op.Data)%blockSize != 0 {
			return "", errors.New("The data must be a multiple of 8 bytes when selecting no padding method")
		}
	}

	// prepare a buffer for the result
	r := make([]byte, blockSize)

	// encrypt the first data block with kl
	kl.Encrypt(r, []byte(op.Data[:blockSize]))

	// loop through the remaining data blocks
	for pos := blockSize; pos < len(op.Data); pos += blockSize {
		// xor the result with the next block
		r = XOR(r, []byte(op.Data[pos:pos+blockSize]))

		// encrypt the result with kl
		kl.Encrypt(r, r)
	}

	kr.Decrypt(r, r)
	kl.Encrypt(r, r)

	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	return result, nil
}
