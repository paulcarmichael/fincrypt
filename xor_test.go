package cryptop

import "testing"

func Test_XOR(t *testing.T) {
	operation := XOROperation{}
	operation.Input1 = "CC99E897"
	operation.Input2 = "12345678"

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "DEADBEEF"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
