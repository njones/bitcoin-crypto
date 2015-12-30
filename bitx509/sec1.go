// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bitx509

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/runeaune/bitcoin-crypto/bitecdsa"
	"github.com/runeaune/bitcoin-crypto/bitelliptic"
	"math/big"
)

const ecPrivKeyVersion = 1

// ecPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//   RFC5915
//   SEC1 - http://www.secg.org/sec1-v2.pdf
// Per RFC5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ParseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
func ParseECPrivateKey(der []byte) (key interface{}, err error) {
	return parseECPrivateKey(nil, der)
}

// MarshalECPrivateKey marshals an EC private key into ASN.1, DER format.
func MarshalECPrivateKey(key *bitecdsa.PrivateKey) ([]byte, error) {
	// TODO(runeaune): Get the actual curve.
	oid, ok := oidFromNamedCurve(bitelliptic.S256())
	if !ok {
		return nil, errors.New("x509: unknown elliptic curve")
	}
	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.Bytes(),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: key.Marshal(key.X, key.Y)},
	})
}

// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *bitecdsa.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	var curve *bitelliptic.BitCurve
	if namedCurveOID != nil {
		curve = namedCurveFromOID(*namedCurveOID)
	} else {
		curve = namedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	if k.Cmp(curve.N) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	return bitecdsa.NewKeyFromInt(curve, k), nil
}
