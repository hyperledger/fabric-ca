/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/ecdsa"

	"crypto/rand"
	"crypto/sha256"

	"crypto/elliptic"

	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

type RevocationAlgorithm int32

const (
	ALG_NO_REVOCATION RevocationAlgorithm = iota
	ALG_PLAIN_SIGNATURE
)

var ProofBytes = map[RevocationAlgorithm]int{
	ALG_NO_REVOCATION:   0,
	ALG_PLAIN_SIGNATURE: 3*(2*FieldBytes+1) + 4*FieldBytes,
}

// GenerateLongTermRevocationKey generates a long term signing key that will be used for revocation
func GenerateLongTermRevocationKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles []*FP256BN.BIG, epoch int, alg RevocationAlgorithm, rng *amcl.RAND) (*CredentialRevocationInformation, error) {
	cri := &CredentialRevocationInformation{}
	cri.RevocationAlg = int32(alg)
	cri.Epoch = int64(epoch)

	// create epoch key
	epochSk, epochPk := WBBKeyGen(rng)
	if alg == ALG_NO_REVOCATION {
		// put a dummy PK in the proto
		cri.EpochPK = Ecp2ToProto(GenG2)
	} else {
		// only put the epoch pk in the proto if we will actually use it
		cri.EpochPK = Ecp2ToProto(epochPk)
	}

	// sign epoch + epoch key with long term key
	bytesToSign, err := proto.Marshal(cri)
	digest := sha256.New().Sum(bytesToSign)

	pkSigR, pkSigS, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	cri.EpochPKSig = append(pkSigR.Bytes(), pkSigS.Bytes()...)

	if alg == ALG_NO_REVOCATION {
		return cri, nil
	} else if alg == ALG_PLAIN_SIGNATURE {
		// create revocationData object
		revocationData := &PlainSigRevocationData{}
		revocationData.Signatures = make([]*MessageSignature, len(unrevokedHandles))
		for i, rh := range unrevokedHandles {
			// sign revocation handle
			sig := WBBSign(epochSk, rh)

			// store revocation handle and signature in revocationData
			revocationData.Signatures[i] = &MessageSignature{BigToBytes(rh), EcpToProto(sig)}
		}

		// serialize the algorithm-specific revocation data
		revocationDataBytes, err := proto.Marshal(revocationData)
		if err != nil {
			return nil, err
		}
		cri.RevocationData = revocationDataBytes

		return cri, nil
	} else {
		return nil, errors.Errorf("the specified revocation algorithm is not supported.")
	}
}

// VerifyEpochPK verifies that the revocation PK for a certain epoch is valid,
// by checking that it was signed with the long term revocation key
func VerifyEpochPK(pk *ecdsa.PublicKey, epochPK *ECP2, epochPkSig []byte, epoch int, alg RevocationAlgorithm) error {
	cri := &CredentialRevocationInformation{}
	cri.RevocationAlg = int32(alg)
	cri.EpochPK = epochPK
	cri.Epoch = int64(epoch)
	bytesToSign, err := proto.Marshal(cri)
	if err != nil {
		return err
	}
	digest := sha256.New().Sum(bytesToSign)
	sigR := &big.Int{}
	sigR.SetBytes(epochPkSig[0 : len(epochPkSig)/2])
	sigS := &big.Int{}
	sigS.SetBytes(epochPkSig[len(epochPkSig)/2:])

	if !ecdsa.Verify(pk, digest, sigR, sigS) {
		return errors.Errorf("EpochPKSig invalid")
	}

	return nil
}
