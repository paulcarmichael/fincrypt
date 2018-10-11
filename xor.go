package cryptop

import (
	"errors"
)

// XOROperation struct to be populated and provided by the caller
type XOROperation struct {
	Input1 string
	Input2 string
}

// Calculate that from tiny acorns do mighty oaks grow
func (op XOROperation) Calculate() (string, error) {
	// validate the input lengths
	if len(op.Input1) != len(op.Input2) {
		return "", errors.New("XOR: Given inputs are different lengths, exiting")
	}

	// pack the data
	var err error
	op.Input1, err = Pack(op.Input1)

	if err != nil {
		return "", err
	}

	op.Input2, err = Pack(op.Input2)

	if err != nil {
		return "", err
	}

	// xor!
	length := len(op.Input1)
	r := make([]byte, length)

	for i := 0; i < length; i++ {
		r[i] = op.Input1[i] ^ op.Input2[i]
	}

	// expand the result
	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	return result, nil
}
