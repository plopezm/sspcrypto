package cryptoutils

import (
	"reflect"
	"testing"
)

func TestDHProcedure(t *testing.T) {
	ckHost := new(SSPCryptoKey)
	ckSlave := new(SSPCryptoKey)

	// Sharing generator and modulus
	ckHost.GenerateGeneratorAndModulus()
	ckSlave.Generator = ckHost.Generator
	ckSlave.Modulus = ckHost.Modulus

	// Creating inter keys
	err := ckHost.CreateHostInterKey()
	if err != nil {
		t.Error("Error creating inter key", err)
	}
	err = ckSlave.CreateHostInterKey()
	if err != nil {
		t.Error("Error creating inter key", err)
	}

	// Setting slave keys using the host key of the opposite
	ckHost.SlaveInterKey = ckSlave.HostInterKey
	ckSlave.SlaveInterKey = ckHost.HostInterKey

	err = ckHost.CreateNegotiatedKey()
	if err != nil {
		t.Error("Error creating encryption key", err)
	}
	err = ckSlave.CreateNegotiatedKey()
	if err != nil {
		t.Error("Error creating encryption key", err)
	}

	if !reflect.DeepEqual(ckHost.Key.NegotiatedKey, ckSlave.Key.NegotiatedKey) {
		t.Error("NegotiatedKey is not equal")
	}

	if !reflect.DeepEqual(ckHost.Key.FinishKey(), ckSlave.Key.FinishKey()) {
		t.Error("MergedKey is not equal")
	}
}

func TestFullKey_FinishKey(t *testing.T) {
	type fields struct {
		FixedKey    int64
		EncryptKey  int64
		CompleteKey []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			name: "128 bits key generated successfully",
			fields: fields{
				FixedKey:   81985526925837671,
				EncryptKey: 1,
			},
			want: []byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ESSPKey{
				FixedKey:      tt.fields.FixedKey,
				NegotiatedKey: tt.fields.EncryptKey,
				MergedKey:     tt.fields.CompleteKey,
			}
			if got := k.FinishKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ESSPKey.FinishKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSPCryptoKey_GetBinaryGenerator(t *testing.T) {
	type fields struct {
		Generator     int64
		Modulus       int64
		HostRandom    int64
		HostInterKey  int64
		SlaveInterKey int64
		Key           ESSPKey
	}
	tests := []struct {
		name          string
		fields        fields
		wantGenerator []byte
	}{
		{
			name: "Converted to litte endian 53432123",
			fields: fields{
				Generator: 53432123,
			},
			wantGenerator: []byte{0x3B, 0x4F, 0x2F, 0x03, 0, 0, 0, 0},
		},
		{
			name: "Converted to litte endian 31245436",
			fields: fields{
				Generator: 31245436,
			},
			wantGenerator: []byte{0x7c, 0xc4, 0xdc, 0x01, 0, 0, 0, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SSPCryptoKey{
				Generator:     tt.fields.Generator,
				Modulus:       tt.fields.Modulus,
				HostRandom:    tt.fields.HostRandom,
				HostInterKey:  tt.fields.HostInterKey,
				SlaveInterKey: tt.fields.SlaveInterKey,
				Key:           tt.fields.Key,
			}
			if gotGenerator := c.GetBinaryGenerator(); !reflect.DeepEqual(gotGenerator, tt.wantGenerator) {
				t.Errorf("SSPCryptoKey.GetBinaryGenerator() = %x, want %x", gotGenerator, tt.wantGenerator)
			}
		})
	}
}

func TestSSPCryptoKey_GetBinaryModulus(t *testing.T) {
	type fields struct {
		Generator     int64
		Modulus       int64
		HostRandom    int64
		HostInterKey  int64
		SlaveInterKey int64
		Key           ESSPKey
	}
	tests := []struct {
		name        string
		fields      fields
		wantModulus []byte
	}{
		{
			name: "Converted to litte endian 53432123",
			fields: fields{
				Modulus: 53432123,
			},
			wantModulus: []byte{0x3B, 0x4F, 0x2F, 0x03, 0, 0, 0, 0},
		},
		{
			name: "Converted to litte endian 31245436",
			fields: fields{
				Modulus: 31245436,
			},
			wantModulus: []byte{0x7c, 0xc4, 0xdc, 0x01, 0, 0, 0, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SSPCryptoKey{
				Generator:     tt.fields.Generator,
				Modulus:       tt.fields.Modulus,
				HostRandom:    tt.fields.HostRandom,
				HostInterKey:  tt.fields.HostInterKey,
				SlaveInterKey: tt.fields.SlaveInterKey,
				Key:           tt.fields.Key,
			}
			if gotModulus := c.GetBinaryModulus(); !reflect.DeepEqual(gotModulus, tt.wantModulus) {
				t.Errorf("SSPCryptoKey.GetBinaryModulus() = %v, want %v", gotModulus, tt.wantModulus)
			}
		})
	}
}

func TestSSPCryptoKey_GetBinaryHostInterKey(t *testing.T) {
	type fields struct {
		Generator     int64
		Modulus       int64
		HostRandom    int64
		HostInterKey  int64
		SlaveInterKey int64
		Key           ESSPKey
	}
	tests := []struct {
		name             string
		fields           fields
		wantHostInterKey []byte
	}{
		{
			name: "Converted to litte endian 53432123",
			fields: fields{
				HostInterKey: 53432123,
			},
			wantHostInterKey: []byte{0x3B, 0x4F, 0x2F, 0x03, 0, 0, 0, 0},
		},
		{
			name: "Converted to litte endian 31245436",
			fields: fields{
				HostInterKey: 31245436,
			},
			wantHostInterKey: []byte{0x7c, 0xc4, 0xdc, 0x01, 0, 0, 0, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SSPCryptoKey{
				Generator:     tt.fields.Generator,
				Modulus:       tt.fields.Modulus,
				HostRandom:    tt.fields.HostRandom,
				HostInterKey:  tt.fields.HostInterKey,
				SlaveInterKey: tt.fields.SlaveInterKey,
				Key:           tt.fields.Key,
			}
			if gotHostInterKey := c.GetBinaryHostInterKey(); !reflect.DeepEqual(gotHostInterKey, tt.wantHostInterKey) {
				t.Errorf("SSPCryptoKey.GetBinaryHostInterKey() = %v, want %v", gotHostInterKey, tt.wantHostInterKey)
			}
		})
	}
}
