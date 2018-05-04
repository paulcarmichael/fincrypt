package cryptop

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AESOperation struct to be populated and provided by the caller
type AESOperation struct {
	Mode int
	Key  string
	Data string
	IV   string
}

// CBC the data should be populated and packed by the caller
func (op AESOperation) CBC() (string, error) {
	// pack the data
	var err error
	op.Key, err = Pack(op.Key)

	if err != nil {
		return "", err
	}

	op.Data, err = Pack(op.Data)

	if err != nil {
		return "", err
	}

	op.IV, err = Pack(op.IV)

	if err != nil {
		return "", err
	}

	// validate the key length
	// 16 - AES-128
	// 32 - AES-256
	keyLength := len(op.Key)

	if keyLength == 16 ||
		keyLength == 32 {
		//happy
	} else {
		return "", errors.New("AES_CBC: Key must be 16/32 bytes")
	}

	// validate the data - it must be a multiple of the blocksize
	dataLength := len(op.Data)

	if dataLength%aes.BlockSize != 0 {
		return "", errors.New("AES_CBC: Data must be padded to a multiple of 16")
	}

	// validate the iv length
	ivLength := len(op.IV)

	if ivLength != 16 {
		return "", errors.New("AES_CBC: IV must be 16 bytes")
	}

	// prepare the key
	keyBytes := []byte(op.Key)

	block, err := aes.NewCipher(keyBytes)

	if err != nil {
		return "", err
	}

	// prepare a buffer for the result
	r := make([]byte, dataLength)

	// the caller specifies the operation mode
	var blockMode cipher.BlockMode

	if op.Mode == Encrypt {
		blockMode = cipher.NewCBCEncrypter(block, []byte(op.IV))
	} else {
		blockMode = cipher.NewCBCDecrypter(block, []byte(op.IV))
	}

	// cipher!
	blockMode.CryptBlocks(r, []byte(op.Data))

	// expand the result
	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	return result, nil
}
