# DID Go Library

A Go implementation of Decentralized Identifiers (DIDs) providing secure identity management with cryptographic key support and hardware wallet integration.

## Overview

This library implements the W3C Decentralized Identifiers (DID) specification, providing a complete solution for creating, managing, and using decentralized identities in Go applications. It supports multiple key types, hardware wallet integration, and seamless integration with cryptographic operations.

## Features

- **DID Creation & Parsing**: Create and parse DIDs according to W3C specification
- **Multiple Key Types**: Support for Ed25519, Secp256k1, and other cryptographic key types
- **Hardware Wallet Integration**: Ledger hardware wallet support for secure key management
- **Cryptographic Operations**: Signing, verification, and key derivation
- **Provider & Anchor Pattern**: Clean separation between private key operations and public verification
- **libp2p Integration**: Native support for libp2p cryptographic operations
- **Comprehensive Testing**: Extensive test coverage including hardware wallet stubs

## Installation

```bash
go get github.com/depinkit/did
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/depinkit/did"
    "gitlab.com/nunet/depinkit/crypto"
)

func main() {
    // Generate a new key pair
    privk, pubk, err := crypto.GenerateKeyPair(crypto.Ed25519)
    if err != nil {
        log.Fatal(err)
    }
    
    // Create a DID from the public key
    did := did.FromPublicKey(pubk)
    fmt.Printf("Created DID: %s\n", did.String())
    
    // Create a provider for signing operations
    provider := did.NewProvider(did, privk)
    
    // Create an anchor for verification operations
    anchor := did.NewAnchor(did, pubk)
    
    // Sign some data
    data := []byte("Hello, DID!")
    signature, err := provider.Sign(data)
    if err != nil {
        log.Fatal(err)
    }
    
    // Verify the signature
    err = anchor.Verify(data, signature)
    if err != nil {
        log.Fatal("Signature verification failed:", err)
    }
    
    fmt.Println("Signature verified successfully!")
}
```

## Core Concepts

### DID Structure

A DID consists of three parts: `did:method:identifier`

```go
type DID struct {
    URI string `json:"uri,omitempty"`
}
```

### Provider & Anchor Pattern

The library uses a clean separation between private key operations (Provider) and public verification (Anchor):

- **Provider**: Handles private key operations like signing
- **Anchor**: Handles public key operations like verification

```go
// Provider for private key operations
type Provider interface {
    DID() DID
    Sign(data []byte) ([]byte, error)
    PrivateKey() (crypto.PrivKey, error)
    Anchor() Anchor
}

// Anchor for public key operations
type Anchor interface {
    DID() DID
    Verify(data []byte, sig []byte) error
    PublicKey() crypto.PubKey
}
```

## Usage Examples

### 1. Creating DIDs from Different Sources

```go
// From a public key
pubk, _ := crypto.GenerateKeyPair(crypto.Ed25519)
did := did.FromPublicKey(pubk)

// From a string
did, err := did.FromString("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

// From a crypto ID
id := crypto.ID("some-crypto-id")
did, err := did.FromID(id)
```

### 2. Hardware Wallet Integration

```go
// Create a Ledger hardware wallet provider
provider, err := did.NewLedgerWalletProvider(0) // Account 0
if err != nil {
    log.Fatal(err)
}

// Get the DID
did := provider.DID()
fmt.Printf("Hardware wallet DID: %s\n", did.String())

// Sign data using the hardware wallet
data := []byte("Secure data")
signature, err := provider.Sign(data)
if err != nil {
    log.Fatal(err)
}

// Get the anchor for verification
anchor := provider.Anchor()
err = anchor.Verify(data, signature)
```

### 3. Key URI Formatting and Parsing

```go
// Format a public key as a DID key URI
pubk, _ := crypto.GenerateKeyPair(crypto.Ed25519)
uri := did.FormatKeyURI(pubk)
fmt.Printf("Key URI: %s\n", uri)

// Parse a key URI back to a public key
parsedPubk, err := did.ParseKeyURI(uri)
if err != nil {
    log.Fatal(err)
}
```

### 4. Context Management

```go
// Create a DID context for managing anchors
ctx := did.NewContext()

// Add an anchor to the context
anchor := did.NewAnchor(did, pubk)
ctx.AddAnchor(anchor)

// Get an anchor from the context
retrievedAnchor, err := ctx.GetAnchor(did)
if err != nil {
    log.Fatal(err)
}

// Verify data using the context
data := []byte("test data")
signature := []byte("signature")
err = ctx.Verify(did, data, signature)
```

### 5. Working with Different Key Types

```go
// Ed25519 keys
ed25519Privk, ed25519Pubk, _ := crypto.GenerateKeyPair(crypto.Ed25519)
ed25519Did := did.FromPublicKey(ed25519Pubk)

// Secp256k1 keys (for hardware wallets)
secp256k1Privk, secp256k1Pubk, _ := crypto.GenerateKeyPair(crypto.Secp256k1)
secp256k1Did := did.FromPublicKey(secp256k1Pubk)

// Create providers for each
ed25519Provider := did.NewProvider(ed25519Did, ed25519Privk)
secp256k1Provider := did.NewProvider(secp256k1Did, secp256k1Privk)
```

## API Reference

### Core Types

- `DID`: Represents a Decentralized Identifier
- `Provider`: Interface for private key operations
- `Anchor`: Interface for public key operations
- `Context`: Manages multiple anchors

### Key Functions

- `FromString(s string) (DID, error)`: Parse a DID from string
- `FromPublicKey(pubk crypto.PubKey) DID`: Create DID from public key
- `FromID(id crypto.ID) (DID, error)`: Create DID from crypto ID
- `NewProvider(did DID, privk crypto.PrivKey) Provider`: Create a provider
- `NewAnchor(did DID, pubk crypto.PubKey) Anchor`: Create an anchor
- `FormatKeyURI(pubk crypto.PubKey) string`: Format key as URI
- `ParseKeyURI(uri string) (crypto.PubKey, error)`: Parse URI to key

### Hardware Wallet Support

- `NewLedgerWalletProvider(account uint32) (Provider, error)`: Create Ledger provider
- `LedgerWalletProvider`: Implementation for Ledger hardware wallets

## Testing

The library includes comprehensive tests including hardware wallet stubs for testing without physical devices:

```bash
go test ./...
```

### Hardware Wallet Testing

```go
// Use the stub for testing without physical hardware
provider := did.NewLedgerWalletProviderStub(0)
did := provider.DID()
// ... test operations
```

## Dependencies

- `github.com/libp2p/go-libp2p/core`: libp2p cryptographic operations
- `github.com/multiformats/go-multibase`: Multibase encoding
- `github.com/multiformats/go-varint`: Variable-length integer encoding
- `github.com/decred/dcrd/dcrec/secp256k1/v4`: Secp256k1 curve support
- `gitlab.com/nunet/depinkit/crypto`: Cryptographic primitives

## License

Apache License 2.0 - see LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure all tests pass and add tests for new functionality.

## Related Projects

- [UCAN](https://github.com/depinkit/ucan): User Controlled Authorization Networks
- [Crypto](https://github.com/depinkit/crypto): Cryptographic primitives
- [Actor](https://github.com/depinkit/actor): Actor model implementation
