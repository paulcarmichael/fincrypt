package cryptop

import "testing"

func Test_AES_ECB_ENC(t *testing.T) {
	operation := AESOperation{}
	operation.Key = "12826172AEDCFBAEFCAEBFAEDCFB3236"
	operation.Data = "34793169017618276876023670293672906729076290679026729076290762105783449245969345692456926925692456926926925892634647585679358699"
	operation.IV = "00000000000000000000000000000000"
	operation.Mode = CipherModeECB
	operation.Direction = DirectionEncrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "65E65C31C1C233DF076575B966ED2ABA0666390742EAD838CD3565F69142E5B849B625C8300CA5664EB00BBDD53D3885C1F6F4521729A3751C3FC7A605600BBB"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_AES_ECB_DEC(t *testing.T) {
	operation := AESOperation{}
	operation.Key = "12826172AEDCFBAEFCAEBFAEDCFB3236"
	operation.Data = "34793169017618276876023670293672906729076290679026729076290762105783449245969345692456926925692456926926925892634647585679358699"
	operation.IV = "00000000000000000000000000000000"
	operation.Mode = CipherModeECB
	operation.Direction = DirectionDecrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "C68E791B390484AD720F758A52D42FA02C14C44EC061AA6F8C6249995E73CF134FC7E1C0F927AF1879F2C29400E31407EACA92E425C0CB244EE74E8DC993057B"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_AES_CBC_ENC(t *testing.T) {
	operation := AESOperation{}
	operation.Key = "12826172AEDCFBAEFCAEBFAEDCFB3236"
	operation.Data = "34793169017618276876023670293672906729076290679026729076290762105783449245969345692456926925692456926926925892634647585679358699"
	operation.IV = "00000000000000000000000000000000"
	operation.Mode = CipherModeCBC
	operation.Direction = DirectionEncrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "65E65C31C1C233DF076575B966ED2ABA99576AA4A604DCF27866C163A70F11CF8011EB6CD575C35C1D6C7D2898F3C5175C84FDA2A6890BB990EAFDA670E94594"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}

func Test_AES_CBC_DEC(t *testing.T) {
	operation := AESOperation{}
	operation.Key = "12826172AEDCFBAEFCAEBFAEDCFB3236"
	operation.Data = "34793169017618276876023670293672906729076290679026729076290762105783449245969345692456926925692456926926925892634647585679358699"
	operation.IV = "00000F000000000000000F0000000000"
	operation.Mode = CipherModeCBC
	operation.Direction = DirectionDecrypt

	result, err := operation.Calculate()

	if err != nil {
		t.Errorf(err.Error())
	}

	expected := "C68E761B390484AD720F7A8A52D42FA0186DF527C117B248E4144BAF2E5AF961DFA0C8C79BB7C8885F8052E229E47617BD49D6766056586127C3181FA0B66C5F"

	if result != expected {
		t.Errorf("Expected [%s], Calculate returned [%s]", expected, result)
	}
}
