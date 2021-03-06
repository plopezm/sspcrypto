package sspcrypto

import (
	"reflect"
	"testing"
)

func TestDHProcedure(t *testing.T) {
	ckHost := new(SSPCryptoKey)
	ckSlave := new(SSPCryptoKey)

	// Generating host generator, modulus and hostInterKey
	err := ckHost.Generate()
	if err != nil {
		t.Error("Error creating inter key", err)
	}

	// Generating slave generator, modulus and hostInterKey
	ckSlave.Generator = ckHost.Generator
	ckSlave.Modulus = ckHost.Modulus
	err = ckSlave.CreateHostInterKey()
	if err != nil {
		t.Error("Error creating inter key", err)
	}

	if reflect.DeepEqual(ckHost.HostInterKey, ckSlave.HostInterKey) {
		t.Error("HostInterKey are equal and they should be different")
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

	if reflect.DeepEqual(ckHost.HostRandom, ckSlave.HostRandom) {
		t.Error("HostRandom are equal and they should be different")
	}

	if !reflect.DeepEqual(ckHost.Key.NegotiatedKey, ckSlave.Key.NegotiatedKey) {
		t.Error("NegotiatedKey are not equal")
	}

	if !reflect.DeepEqual(ckHost.Key.MergeKeys(), ckSlave.Key.MergeKeys()) {
		t.Error("EncryptionKey are not equal")
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
				EncryptionKey: tt.fields.CompleteKey,
			}
			if got := k.MergeKeys(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ESSPKey.MergeKeys() = %v, want %v", got, tt.want)
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
			name: "Converted to little endian 53432123",
			fields: fields{
				Generator: 53432123,
			},
			wantGenerator: []byte{0x3B, 0x4F, 0x2F, 0x03, 0, 0, 0, 0},
		},
		{
			name: "Converted to little endian 31245436",
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
			name: "Converted to little endian 53432123",
			fields: fields{
				Modulus: 53432123,
			},
			wantModulus: []byte{0x3B, 0x4F, 0x2F, 0x03, 0, 0, 0, 0},
		},
		{
			name: "Converted to little endian 31245436",
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
			name: "Converted to little endian 53432123",
			fields: fields{
				HostInterKey: 53432123,
			},
			wantHostInterKey: []byte{0x3B, 0x4F, 0x2F, 0x03, 0, 0, 0, 0},
		},
		{
			name: "Converted to little endian 31245436",
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

func TestSSPCryptoKey_SetSlaveInterKey(t *testing.T) {
	type fields struct {
		Generator     int64
		Modulus       int64
		HostRandom    int64
		HostInterKey  int64
		SlaveInterKey int64
		Key           ESSPKey
	}
	type args struct {
		slaveInterKey []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int64
	}{
		{
			name: "Converted from little endian 53432123",
			fields: fields{
				HostInterKey: 0,
			},
			args: args{
				slaveInterKey: []byte{0x3B, 0x4F, 0x2F, 0x03, 0, 0, 0, 0},
			},
			want: 53432123,
		},
		{
			name: "Converted from little endian 31245436",
			fields: fields{
				HostInterKey: 0,
			},
			args: args{
				slaveInterKey: []byte{0x7c, 0xc4, 0xdc, 0x01, 0, 0, 0, 0},
			},
			want: 31245436,
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
			if c.SetSlaveInterKey(tt.args.slaveInterKey); !reflect.DeepEqual(c.SlaveInterKey, tt.want) {
				t.Errorf("SSPCryptoKey.SetSlaveInterKey() = %x, want %x", c.SlaveInterKey, tt.want)
			}
		})
	}
}
