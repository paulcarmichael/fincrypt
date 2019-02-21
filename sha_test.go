package fincrypt

import "testing"

func Test_SHA1(t *testing.T) {
	operation := SHAOperation{}
	operation.Input = "makin'hasheatin'mashspendin'cash"
	operation.Mode = SHAModeSHA1

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "991867694d2384605811ee49cd93c1216ac8dee4"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_SHA_224(t *testing.T) {
	operation := SHAOperation{}
	operation.Input = "makin'hasheatin'mashspendin'cash"
	operation.Mode = SHAModeSHA224

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "acc3391cb9d4a40ef4e13fb32ee49326ee55083d91ff8c070d226768"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_SHA_256(t *testing.T) {
	operation := SHAOperation{}
	operation.Input = "makin'hasheatin'mashspendin'cash"
	operation.Mode = SHAModeSHA256

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "5dd8d7b4c2d7cb980b7744bdbb607fd9b508e248d2463423744da2914ee7945d"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_SHA_384(t *testing.T) {
	operation := SHAOperation{}
	operation.Input = "makin'hasheatin'mashspendin'cash"
	operation.Mode = SHAModeSHA384

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "4ed7c85e025c4be588a6146da8393f869e0a98af4a88fe640e80f8fcd4c48b89b70fa3d8f4dfa7ab54ffd1fed00441e2"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_SHA_512(t *testing.T) {
	operation := SHAOperation{}
	operation.Input = "makin'hasheatin'mashspendin'cash"
	operation.Mode = SHAModeSHA512

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "d9c2e339fe0b2f01e265bf00c3828393458cdefa3403dc5f3344dd5366cd13b9423236247d15a60d2cfa09e1fddaedc4734db337061aa649bc350759c9959993"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
