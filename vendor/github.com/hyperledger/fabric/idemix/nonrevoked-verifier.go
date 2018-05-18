/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

type nonRevokedVerifier interface {
	recomputeFSContribution(proof *NonRevokedProof, chal *FP256BN.BIG, epochPK *FP256BN.ECP2, proofSRh *FP256BN.BIG) ([]byte, error)
}
type nopNonRevokedVerifier struct{}

func (verifier *nopNonRevokedVerifier) recomputeFSContribution(proof *NonRevokedProof, chal *FP256BN.BIG, epochPK *FP256BN.ECP2, proofSRh *FP256BN.BIG) ([]byte, error) {
	return nil, nil
}

func getNonRevocationVerifier(algorithm RevocationAlgorithm) (nonRevokedVerifier, error) {
	switch algorithm {
	case ALG_NO_REVOCATION:
		return &nopNonRevokedVerifier{}, nil
	case ALG_PLAIN_SIGNATURE:
		return &plainSigNonRevokedVerifier{}, nil
	default:
		// unknown revocation algorithm
		return nil, errors.Errorf("unknown revocation algorithm %d", algorithm)
	}
}

type plainSigNonRevokedVerifier struct{}

func (verifier *plainSigNonRevokedVerifier) recomputeFSContribution(proof *NonRevokedProof, chal *FP256BN.BIG, epochPK *FP256BN.ECP2, proofSRh *FP256BN.BIG) ([]byte, error) {
	proofUnmarshaled := &PlainSigNonRevokedProof{}
	err := proto.Unmarshal(proof.NonRevokedProof, proofUnmarshaled)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal non-revoked proof")
	}

	sigBar := EcpFromProto(proofUnmarshaled.SigmaBar)
	sigPrime := EcpFromProto(proofUnmarshaled.SigmaPrime)
	if sigPrime.Is_infinity() {
		return nil, errors.Errorf("Nonrevoked proof is invalid, sigPrime = 1")
	}

	// Check whether sigBar and sigPrime have the right structure
	minSigPrime := FP256BN.NewECP()
	minSigPrime.Sub(sigPrime)

	result := FP256BN.Fexp(FP256BN.Ate2(epochPK, minSigPrime, GenG2, sigBar))
	if !result.Isunity() {
		return nil, errors.Errorf("SigmaBar and SigmaPrime don't have the expected structure")
	}

	t := sigPrime.Mul2(FP256BN.Modneg(proofSRh, GroupOrder), GenG1, FP256BN.FromBytes(proofUnmarshaled.ProofSR))
	t.Sub(sigBar.Mul(chal))

	// fsBytes will hold three elements of G1, each taking 2*FieldBytes+1 bytes, and one element of G2, which takes 4*FieldBytes
	fsBytes := make([]byte, 3*(2*FieldBytes+1)+4*FieldBytes)
	index := appendBytesG1(fsBytes, 0, sigBar)
	index = appendBytesG1(fsBytes, index, sigPrime)
	index = appendBytesG2(fsBytes, index, epochPK)
	index = appendBytesG1(fsBytes, index, t)

	return fsBytes, nil
}
