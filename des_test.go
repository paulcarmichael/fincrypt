package fincrypt

import "testing"

func Test_DES_ECB_ENC(t *testing.T) {
	operation := DESOperation{}
	operation.Key = "FFEEDDCCBBAA0099"
	operation.Data = "1122334455667788FFFFFFFFBBABCD22"
	operation.IV = "0000000000000000"
	operation.Mode = CipherModeECB
	operation.Direction = DirectionEncrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "E4236C852CCBA6840C7816E390479B6B"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_DES_ECB_DEC(t *testing.T) {
	operation := DESOperation{}
	operation.Key = "FFEEDDCCBBAA0099"
	operation.Data = "1122334455667788FFFFFFFFBBABCD22"
	operation.IV = "0000000000000000"
	operation.Mode = CipherModeECB
	operation.Direction = DirectionDecrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "C3C3E1A99E45774F1AEFF948D145A0A5"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_DES_CBC_ENC(t *testing.T) {
	operation := DESOperation{}
	operation.Key = "FFEEDDCCBBAA0099"
	operation.Data = "1122334455667788FFFFFFFFBBABCD22"
	operation.IV = "0000000000000000"
	operation.Mode = CipherModeCBC
	operation.Direction = DirectionEncrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "E4236C852CCBA68431DF1813D9E140CE"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_DES_CBC_DEC(t *testing.T) {
	operation := DESOperation{}
	operation.Key = "FFEEDDCCBBAA0099"
	operation.Data = "1122334455667788FFFFFFFFBBABCD22"
	operation.IV = "0000000000000000"
	operation.Mode = CipherModeCBC
	operation.Direction = DirectionDecrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "C3C3E1A99E45774F0BCDCA0C8423D72D"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_TDES_ECB_ENC(t *testing.T) {
	operation := DESOperation{}
	operation.Key = "FFEEDDCCBBAA0099394857123DEABCD6"
	operation.Data = "1122334455667788FFFFFFFFBBABCD22"
	operation.IV = "0000000000000000"
	operation.Mode = CipherModeECB
	operation.Direction = DirectionEncrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "6541A40B7FC8F4F45BA8C877A3EBB52B"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_TDES_ECB_DEC(t *testing.T) {
	operation := DESOperation{}
	operation.Key = "FFEEDDCCBBAA0099394857123DEABCD6"
	operation.Data = "1122334455667788FFFFFFFFBBABCD22"
	operation.IV = "000F000000000000"
	operation.Mode = CipherModeECB
	operation.Direction = DirectionDecrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "F8BE6B65F05BCC403842F2F56C1B5D65"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_TDES_CBC_ENC(t *testing.T) {
	operation := DESOperation{}
	operation.Key = "FFEEDDCCBBAA0099394857123DEABCD6"
	operation.Data = "1122334455667788FFFFFFFFBBABCD22"
	operation.IV = "000F000000000000"
	operation.Mode = CipherModeCBC
	operation.Direction = DirectionEncrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "5C507E16682375303FD5365CC208B36E"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_TDES_CBC_DEC(t *testing.T) {
	operation := DESOperation{}
	operation.Key = "FFEEDDCCBBAA0099394857123DEABCD6"
	operation.Data = "1122334455667788FFFFFFFFBBABCD22"
	operation.IV = "000F000000000000"
	operation.Mode = CipherModeCBC
	operation.Direction = DirectionDecrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "F8B16B65F05BCC402960C1B1397D2AED"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
