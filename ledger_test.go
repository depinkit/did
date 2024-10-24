// Copyright 2024, Nunet
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

//go:build ledger
// +build ledger

package did

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLedgerProvider(t *testing.T) {
	prov, err := NewLedgerWalletProvider(0)
	require.NoError(t, err)

	data := []byte("i am a walrus")
	sig, err := prov.Sign(data)
	require.NoError(t, err)

	anchor := prov.Anchor()
	err = anchor.Verify(data, sig)
	require.NoError(t, err)
}

func TestLedgerDID(t *testing.T) {
	prov, err := NewLedgerWalletProvider(0)
	require.NoError(t, err)

	didStr := prov.DID().String()
	did, err := FromString(didStr)
	require.NoError(t, err)

	pubk, err := PublicKeyFromDID(did)
	require.NoError(t, err)

	anchor, err := AnchorFromPublicKey(pubk)
	require.NoError(t, err)

	data := []byte("i am a walrus")
	sig, err := prov.Sign(data)
	require.NoError(t, err)
	err = anchor.Verify(data, sig)
	require.NoError(t, err)
}
