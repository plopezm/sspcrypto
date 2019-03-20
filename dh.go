package sspcrypto

import (
	"encoding/binary"
	"errors"
	"math/rand"
)

type SSPCryptoKey struct {
	Generator     int64
	Modulus       int64
	HostRandom    int64
	HostInterKey  int64
	SlaveInterKey int64
	Key           ESSPKey
}

func (c *SSPCryptoKey) Generate() error {
	c.GenerateGeneratorAndModulus()
	return c.CreateHostInterKey()
}

func (c *SSPCryptoKey) GenerateGeneratorAndModulus() {
	var prime1 uint64
	var prime2 uint64

	for prime1 == prime2 {
		prime1 = GeneratePrime()
		prime2 = GeneratePrime()
	}
	if prime1 > prime2 {
		c.Generator = int64(prime1)
		c.Modulus = int64(prime2)
	} else {
		c.Generator = int64(prime2)
		c.Modulus = int64(prime1)
	}
	return
}

func (c *SSPCryptoKey) CreateHostInterKey() error {
	if c.Generator == 0 || c.Modulus == 0 {
		return errors.New("generator and modulus must be set")
	}
	c.HostRandom = rand.Int63() % MAX_RANDOM_INTEGER;
	c.HostInterKey = XpowYmodN(c.Generator, c.HostRandom, c.Modulus)
	return nil
}

func (c *SSPCryptoKey) CreateNegotiatedKey() error {
	if c.SlaveInterKey == 0 {
		return errors.New("SlaveInterKey not set")
	}
	c.Key.NegotiatedKey = XpowYmodN(c.SlaveInterKey, c.HostRandom, c.Modulus)
	return nil
}

func (c *SSPCryptoKey) SetSlaveInterKey(slaveInterKey []byte) {
	c.SlaveInterKey = 0
	for i:= 0;i < 8 ; i++ {
		c.SlaveInterKey += int64(slaveInterKey[i]) << uint64(i*8);
	}
}

func (c *SSPCryptoKey) GetBinaryGenerator() (generator []byte) {
	generator = make([]byte, 8)
	for i:= 0;i < 8 ; i++ {
		generator[i] = byte(c.Generator >> uint64(i*8));
	}
	return generator
}

func (c *SSPCryptoKey) GetBinaryModulus() (modulus []byte) {
	modulus = make([]byte, 8)
	for i:= 0;i < 8 ; i++ {
		modulus[i] = byte(c.Modulus >> uint64(i*8));
	}
	return modulus
}

func (c *SSPCryptoKey) GetBinaryHostInterKey() (hostInterKey []byte) {
	hostInterKey = make([]byte, 8)
	for i:= 0;i < 8 ; i++ {
		hostInterKey[i] = byte(c.HostInterKey >> uint64(i*8));
	}
	return hostInterKey
}

type ESSPKey struct {
	FixedKey      int64
	NegotiatedKey int64
	EncryptionKey []byte
}

func (k ESSPKey) MergeKeys() []byte {
	k.EncryptionKey = make([]byte, 16)
	binary.LittleEndian.PutUint64(k.EncryptionKey, uint64(k.FixedKey))
	binary.LittleEndian.PutUint64(k.EncryptionKey[8:], uint64(k.NegotiatedKey))
	return k.EncryptionKey
}
