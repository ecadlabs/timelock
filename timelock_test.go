package timelock

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLowLevel(t *testing.T) {
	time := 10_000

	timelockPrecomputedTuple, err := PrecomputeTimelock(rand.Reader, time, nil)
	require.NoError(t, err)

	locked, proof, err := timelockPrecomputedTuple.Proof(rand.Reader, time, nil)
	require.NoError(t, err)
	require.True(t, Verify(locked, proof, time, nil))

	proof2 := UnlockAndProve(time, locked, nil)
	assert.True(t, Verify(locked, proof2, time, nil))

	symKey1 := proof.SymmetricKey(nil)
	symKey2 := proof2.SymmetricKey(nil)
	assert.Equal(t, symKey1, symKey2)

	message := []byte("rzersef")
	c, err := Encrypt(rand.Reader, &symKey2, message)
	require.NoError(t, err)

	d, ok := Decrypt(&symKey2, c)
	assert.True(t, ok)
	assert.Equal(t, message, d)
}

func TestChest(t *testing.T) {
	time := 10_000
	payload := []byte("zrethgfdsq")
	chest, chestKey1, err := NewChestAndChestKey(rand.Reader, payload, time, nil)
	require.NoError(t, err)
	chestKey2, err := chest.NewKey(time, nil)
	require.NoError(t, err)

	op1, ok, err := chest.Open(chestKey1, time, nil)
	require.NoError(t, err)
	assert.True(t, ok)

	op2, ok, err := chest.Open(chestKey2, time, nil)
	require.NoError(t, err)
	assert.True(t, ok)

	assert.Equal(t, payload, op1)
	assert.Equal(t, op1, op2)
}
