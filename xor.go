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
		return "", errors.New("Given inputs are different lengths")
	}

	// pack the data
	var err error
	op.Input1, err = Pack(op.Input1, InputNameInput)

	if err != nil {
		return "", err
	}

	op.Input2, err = Pack(op.Input2, InputNameInput)

	if err != nil {
		return "", err
	}

	// xor!
	r := XOR([]byte(op.Input1), []byte(op.Input2))

	// expand the result
	result, err := Expand(r)

	if err != nil {
		return "", err
	}

	return result, nil
}
