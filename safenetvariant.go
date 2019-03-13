package fincrypt

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
	"strings"
)

// SafeNetVariantOperation instance to be instantiated and populated by the caller
type SafeNetVariantOperation struct {
	MK        string
	Variant   string
	Key       string
	Direction Direction
}

// Calculate uses a Master Key variant to result in a clear key from an encrypted key or an encrypted key from a clear key
func (op SafeNetVariantOperation) Calculate() (string, error) {
	// validate the inputs
	if len(op.MK) != 32 {
		return "", errors.New("Master Key must be 16 bytes (32 digits) in length")
	}

	if len(op.Variant) != 2 {
		return "", errors.New("Variant must be 1 byte (2 digits) in length")
	}
	op.Variant = strings.Repeat(op.Variant, 16)

	if len(op.Key) != 32 {
		return "", errors.New("Key must be 16 bytes (32 digits) in length")
	}

	// prepare the inputs
	var err error
	op.MK, err = Pack(op.MK, InputNameMasterKey)

	if err != nil {
		return "", err
	}

	op.Variant, err = Pack(op.Variant, InputNameVariant)

	if err != nil {
		return "", err
	}

	op.Key, err = Pack(op.Key, InputNameKey)

	if err != nil {
		return "", err
	}

	// prepare the Master Key variant
	tMK := XOR([]byte(op.MK), []byte(op.Variant))

	vMK := make([]byte, len(tMK)+8)
	copy(vMK, tMK)
	copy(vMK[16:], tMK[:8])

	block, err := des.NewTripleDESCipher(vMK)

	if err != nil {
		return "", err
	}

	// prepare the IV
	iv := make([]byte, block.BlockSize())

	var blockMode cipher.BlockMode

	if op.Direction == DirectionEncrypt {
		blockMode = cipher.NewCBCEncrypter(block, iv)
	} else {
		blockMode = cipher.NewCBCDecrypter(block, iv)
	}

	// calculate the result
	r := make([]byte, len(op.Key))

	blockMode.CryptBlocks(r, []byte(op.Key))

	// expand the result
	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	return result, nil
}
