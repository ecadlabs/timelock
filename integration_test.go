//go:build integration

package timelock_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/client"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/encoding"
	"github.com/ecadlabs/gotez/v2/protocol/core"
	"github.com/ecadlabs/gotez/v2/protocol/core/expression"
	"github.com/ecadlabs/gotez/v2/protocol/latest"
	"github.com/ecadlabs/gotez/v2/teztool"
	"github.com/ecadlabs/timelock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	chainID = "NetXnHfVqm9iesp"
	address = "KT1L5vut1xc4hYQtFc77ydh1RseTfHs5wqw4"
	url     = "https://ghostnet.ecadinfra.com"
	time    = 10_000
)

type logger struct{}

func (logger) Printf(format string, a ...any) {
	fmt.Printf(format, a...)
	fmt.Printf("\n")
}

func TestRoundtrip(t *testing.T) {
	chain, _ := b58.ParseChainID([]byte(chainID))
	addr, _ := b58.ParseContractHash([]byte(address))
	c := client.Client{
		URL: url,
	}
	sk, err := b58.ParsePrivateKey([]byte(os.Getenv("PRIVATE_KEY")))
	require.NoError(t, err)
	priv, err := crypt.NewPrivateKey(sk)
	require.NoError(t, err)

	var payload [64]byte
	_, err = io.ReadFull(rand.Reader, payload[:])
	require.NoError(t, err)

	chest, key, err := timelock.NewChest(rand.Reader, payload[:], time, nil)
	require.NoError(t, err)
	var chestBytes, keyBytes bytes.Buffer
	require.NoError(t, encoding.Encode(&chestBytes, chest))
	require.NoError(t, encoding.Encode(&keyBytes, key))

	tool := teztool.New(&c, chain)
	tool.DebugLogger = logger{}
	signer := teztool.NewLocalSigner(priv)
	tx := latest.Transaction{
		ManagerOperation: latest.ManagerOperation{
			Source: priv.Public().Hash(),
		},
		Amount:      tz.BigUZero(),
		Destination: core.OriginatedContract{ContractHash: addr},
		Parameters: tz.Some(latest.Parameters{
			Entrypoint: latest.EpDefault{},
			Value: &expression.Prim20{
				Prim: expression.Prim_Pair,
				Args: [2]expression.Expression{
					expression.Bytes{Bytes: chestBytes.Bytes()},
					expression.Bytes{Bytes: keyBytes.Bytes()},
				},
			},
		}),
	}
	spew.Dump(&tx)
	grp, err := tool.FillSignAndInjectWait(context.Background(), signer, []latest.OperationContents{&tx}, client.MetadataAlways, teztool.FillAll)
	if err != nil {
		var e *client.Error
		if errors.As(err, &e) {
			spew.Dump(e.Body)
		}
	}
	require.NoError(t, err)
	ops := grp.GetContents().Operations()
	require.Equal(t, 1, len(ops))
	storage := ops[0].(*latest.TransactionContentsAndResult).
		Metadata.OperationResult.(*core.OperationResultApplied[latest.TransactionResultDestination]).
		Contents.(*latest.ToContract).Storage
	require.True(t, storage.IsSome())
	expect := &expression.Prim10{
		Prim: expression.Prim_Some,
		Arg:  expression.Bytes{Bytes: tz.Bytes(payload[:])},
	}
	assert.Equal(t, expect, storage.Unwrap())
}
