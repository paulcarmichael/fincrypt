package fincrypt

import "testing"

func Test_MD4(t *testing.T) {
	operation := MDOperation{}
	operation.Input = "makin'hasheatin'mashspendin'cash"
	operation.Mode = MDModeMD4

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "3c7ae0864f79b0fc56d2aea1d89edab4"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_MD5(t *testing.T) {
	operation := MDOperation{}
	operation.Input = "makin'hasheatin'mashspendin'cash"
	operation.Mode = MDModeMD5

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "082e91a5a743e0129abfa1aee50df05c"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
