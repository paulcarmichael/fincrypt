package fincrypt

import "testing"

func Test_SafeNetVariant_ENC(t *testing.T) {
	operation := SafeNetVariantOperation{}
	operation.MK = "0123456789ABCDEFFEDCBA9876543210"
	operation.Variant = "7E"
	operation.Key = "5EB3BCFB75C7923E388CBF6DC4525D86"
	operation.Direction = DirectionEncrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "318062422B5745118485156CCF4B19C9"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_SafeNetVariant_DEC(t *testing.T) {
	operation := SafeNetVariantOperation{}
	operation.MK = "0123456789ABCDEFFEDCBA9876543210"
	operation.Variant = "30"
	operation.Key = "3078E4DD68422A2F982C128F87A1A09C"
	operation.Direction = DirectionDecrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "08A4AE9E6438C26108C240FE1325AD0B"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
