package cryptop

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
)

// DESOperation struct to be populated by the caller
type DESOperation struct {
	Direction int
	Mode      string
	Key       string
	Data      string
	IV        string
}

// Calculate performs a crypto operation as described in the DESOperation varible, which should be populated be the caller
func (op DESOperation) Calculate() (string, error) {
	// pack the key, data, and IV
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
	keyLength := len(op.Key)

	if keyLength == 8 || // DES
		keyLength == 16 || // TDES, first key used twice
		keyLength == 24 { // TDES
		// happy
	} else {
		return "", errors.New("Key must be 8/16/24 bytes")
	}

	// prepare the key
	var block cipher.Block

	if keyLength == 8 {
		block, err = des.NewCipher([]byte(op.Key))

		if err != nil {
			return "", err
		}
	} else if keyLength == 16 {
		// duplicate the first 8 bytes to build a 24 byte key
		op.Key += op.Key[:8]

		block, err = des.NewTripleDESCipher([]byte(op.Key))

		if err != nil {
			return "", err
		}
	} else {
		block, err = des.NewTripleDESCipher([]byte(op.Key))

		if err != nil {
			return "", err
		}
	}

	// validate the data - it must be a multiple of the block size
	blockSize := block.BlockSize()

	if len(op.Data)%blockSize != 0 {
		return "", errors.New("Data length must be a multiple of the block size (8 bytes)")
	}

	// prepare a buffer for the result
	r := make([]byte, len(op.Data))

	// the caller specifies the direction and mode
	if op.Mode == ModeCBC {
		// validate the iv length
		if len(op.IV) != 8 {
			return "", errors.New("IV must be 8 bytes")
		}

		var blockMode cipher.BlockMode

		if op.Direction == DirectionEncrypt {
			blockMode = cipher.NewCBCEncrypter(block, []byte(op.IV))
		} else {
			blockMode = cipher.NewCBCDecrypter(block, []byte(op.IV))
		}

		blockMode.CryptBlocks(r, []byte(op.Data))
	} else if op.Mode == ModeECB { // cipher provides no EBC crypters, so do it manually by the block
		data := []byte(op.Data)

		if op.Direction == DirectionEncrypt {
			for blockStart, blockEnd := 0, blockSize; blockStart < len(op.Data); blockStart, blockEnd = blockStart+blockSize, blockEnd+blockSize {
				block.Encrypt(r[blockStart:blockEnd], data[blockStart:blockEnd])
			}
		} else {
			for blockStart, blockEnd := 0, blockSize; blockStart < len(op.Data); blockStart, blockEnd = blockStart+blockSize, blockEnd+blockSize {
				block.Decrypt(r[blockStart:blockEnd], data[blockStart:blockEnd])
			}
		}
	}

	// expand the result
	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	return result, nil
}
