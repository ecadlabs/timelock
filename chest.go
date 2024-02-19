package timelock

import (
	"io"
	"math/big"

	"golang.org/x/crypto/nacl/secretbox"
)

type Chest struct {
	LockedValue *big.Int
	CipherText  CipherText
}

type CipherText struct {
	Payload []byte
	Nonce   [24]byte
}

type ChestKey = TimelockProof

func Encrypt(random io.Reader, key *[32]byte, payload []byte) (*CipherText, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return nil, err
	}
	text := secretbox.Seal(nil, payload, &nonce, key)
	return &CipherText{
		Payload: text,
		Nonce:   nonce,
	}, nil
}

func Decrypt(key *[32]byte, c *CipherText) ([]byte, bool) {
	return secretbox.Open(nil, c.Payload, &c.Nonce, key)
}

func NewChestAndChestKey(random io.Reader, payload []byte, time int, mod *big.Int) (chest *Chest, key *ChestKey, err error) {
	if time <= 0 {
		return nil, nil, ErrInvalidArgument
	}
	vdfTuple, err := PrecomputeTimelock(random, time, mod)
	if err != nil {
		return nil, nil, err
	}
	lockedValue, proof, err := vdfTuple.Proof(random, time, mod)
	if err != nil {
		return nil, nil, err
	}
	symKey := proof.SymmetricKey(mod)
	cipherText, err := Encrypt(random, &symKey, payload)
	if err != nil {
		return nil, nil, err
	}
	return &Chest{
		LockedValue: lockedValue,
		CipherText:  *cipherText,
	}, proof, nil
}

func (chest *Chest) NewKey(time int, mod *big.Int) (key *ChestKey, err error) {
	if time <= 0 {
		return nil, ErrInvalidArgument
	}
	return UnlockAndProve(time, chest.LockedValue, mod), nil
}

func (chest *Chest) Open(key *ChestKey, time int, mod *big.Int) ([]byte, bool, error) {
	if time <= 0 {
		return nil, false, ErrInvalidArgument
	}
	if !Verify(chest.LockedValue, key, time, mod) {
		return nil, false, nil
	}
	symKey := key.SymmetricKey(mod)
	out, ok := Decrypt(&symKey, &chest.CipherText)
	return out, ok, nil
}
