package cryptop

import "testing"

func Test_Base64_Encode(t *testing.T) {
	operation := Base64Operation{}
	operation.Direction = DirectionEncrypt
	operation.Input = "VkFMQVJJVEFT"

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "VmtGTVFWSkpWRUZU"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_Base64_Decode(t *testing.T) {
	operation := Base64Operation{}
	operation.Direction = DirectionDecrypt
	operation.Input = "VkFMQVJJVEFT"

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "VALARITAS"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
