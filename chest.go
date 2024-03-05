package timelock

import (
	"io"
	"math/big"

	tz "github.com/ecadlabs/gotez/v2"
	"golang.org/x/crypto/nacl/secretbox"
)

type Chest struct {
	LockedValue tz.BigUint `json:"locked_value"`
	CipherText  CipherText `json:"ciphertext"`
}

type CipherText struct {
	Nonce   [24]byte `json:"nonce"`
	Payload []byte   `tz:"dyn" json:"payload"`
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

func NewChest(random io.Reader, payload []byte, time int, mod *big.Int) (chest *Chest, key *ChestKey, err error) {
	if time <= 0 {
		return nil, nil, ErrInvalidArgument
	}
	vdfTuple, err := PrecomputeTimelock(random, time, mod)
	if err != nil {
		return nil, nil, err
	}
	return NewChestFromTimelock(random, payload, time, vdfTuple, mod)
}

func NewChestFromTimelock(random io.Reader, payload []byte, time int, timelock *Timelock, mod *big.Int) (chest *Chest, key *ChestKey, err error) {
	if time <= 0 {
		return nil, nil, ErrInvalidArgument
	}
	lockedValue, proof, err := timelock.NewProof(random, time, mod)
	if err != nil {
		return nil, nil, err
	}
	symKey := proof.SymmetricKey(mod)
	cipherText, err := Encrypt(random, &symKey, payload)
	if err != nil {
		return nil, nil, err
	}
	return &Chest{
		LockedValue: newBigUintUnsafe(lockedValue),
		CipherText:  *cipherText,
	}, proof, nil
}

func (chest *Chest) NewKey(time int, mod *big.Int) (key *ChestKey, err error) {
	if time <= 0 {
		return nil, ErrInvalidArgument
	}
	return UnlockAndProve(time, chest.LockedValue.Int(), mod), nil
}

func (chest *Chest) Open(key *ChestKey, time int, mod *big.Int) ([]byte, bool, error) {
	if time <= 0 {
		return nil, false, ErrInvalidArgument
	}
	if !Verify(chest.LockedValue.Int(), key, time, mod) {
		return nil, false, nil
	}
	symKey := key.SymmetricKey(mod)
	out, ok := Decrypt(&symKey, &chest.CipherText)
	return out, ok, nil
}
