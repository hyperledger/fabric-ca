/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"reflect"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

type nonRevokedProver interface {
	getFSContribution(rh *FP256BN.BIG, rRh *FP256BN.BIG, cri *CredentialRevocationInformation, rng *amcl.RAND) ([]byte, error)
	getNonRevokedProof(chal *FP256BN.BIG) (*NonRevokedProof, error)
}
type nopNonRevokedProver struct{}

func (prover *nopNonRevokedProver) getFSContribution(rh *FP256BN.BIG, rRh *FP256BN.BIG, cri *CredentialRevocationInformation, rng *amcl.RAND) ([]byte, error) {
	return nil, nil
}
func (prover *nopNonRevokedProver) getNonRevokedProof(chal *FP256BN.BIG) (*NonRevokedProof, error) {
	ret := &NonRevokedProof{}
	ret.RevocationAlg = int32(ALG_NO_REVOCATION)
	return ret, nil
}

func getNonRevocationProver(algorithm RevocationAlgorithm) (nonRevokedProver, error) {
	switch algorithm {
	case ALG_NO_REVOCATION:
		return &nopNonRevokedProver{}, nil
	case ALG_PLAIN_SIGNATURE:
		return &plainSigNonRevokedProver{}, nil
	default:
		// unknown revocation algorithm
		return nil, errors.Errorf("unknown revocation algorithm %d", algorithm)
	}
}

type plainSigNonRevokedProver struct {
	rh       *FP256BN.BIG // revocation handle
	rRh      *FP256BN.BIG // r-value used in proving knowledge of rh
	sig      *FP256BN.ECP // signature on rh
	randSig  *FP256BN.BIG // randomness used to randomize sig
	rRandSig *FP256BN.BIG // r-value used in proving knowledge of randSig
	sigPrime *FP256BN.ECP // sig^randSig
	sigBar   *FP256BN.ECP // sigPrime^-rh * genG1^randSig
}

func (prover *plainSigNonRevokedProver) getFSContribution(rh *FP256BN.BIG, rRh *FP256BN.BIG, cri *CredentialRevocationInformation, rng *amcl.RAND) ([]byte, error) {
	if cri.RevocationAlg != int32(ALG_PLAIN_SIGNATURE) {
		return nil, errors.Errorf("the credential revocation revocation is not for ALG_PLAIN_SIGNATURE")
	}
	revocationData := &PlainSigRevocationData{}
	err := proto.Unmarshal(cri.RevocationData, revocationData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal revocation data")
	}

	prover.rh = rh
	prover.rRh = rRh
	rhBytes := BigToBytes(rh)

	for _, m := range revocationData.Signatures {
		if reflect.DeepEqual(rhBytes, m.RevocationHandle) {
			prover.sig = EcpFromProto(m.RHSignature)
			break
		}
	}
	if prover.sig == nil {
		return nil, errors.Errorf("no signature for the revocation handle found in the cri, signer is probably revoked")
	}

	// prove knowledge of sig with the ZKP from Camenisch-Drijvers-Hajny: "Scalable Revocation Scheme
	// for Anonymous Credentials Based on n-times Unlinkable Proofs"
	prover.randSig = RandModOrder(rng)
	prover.sigPrime = prover.sig.Mul(prover.randSig)
	prover.sigBar = prover.sigPrime.Mul2(FP256BN.Modneg(prover.rh, GroupOrder), GenG1, prover.randSig)
	prover.rRandSig = RandModOrder(rng)

	t := prover.sigPrime.Mul2(FP256BN.Modneg(prover.rRh, GroupOrder), GenG1, prover.rRandSig)

	// fsBytes will hold three elements of G1, each taking 2*FieldBytes+1 bytes, and one element of G2, which takes 4*FieldBytes
	fsBytes := make([]byte, 3*(2*FieldBytes+1)+4*FieldBytes)
	index := appendBytesG1(fsBytes, 0, prover.sigBar)
	index = appendBytesG1(fsBytes, index, prover.sigPrime)
	index = appendBytesG2(fsBytes, index, Ecp2FromProto(cri.EpochPK))
	index = appendBytesG1(fsBytes, index, t)

	return fsBytes, nil
}

func (prover *plainSigNonRevokedProver) getNonRevokedProof(chal *FP256BN.BIG) (*NonRevokedProof, error) {
	ret := &NonRevokedProof{}
	ret.RevocationAlg = int32(ALG_PLAIN_SIGNATURE)

	proof := &PlainSigNonRevokedProof{}

	proof.ProofSR = BigToBytes(Modadd(prover.rRandSig, FP256BN.Modmul(prover.randSig, chal, GroupOrder), GroupOrder))
	proof.SigmaBar = EcpToProto(prover.sigBar)
	proof.SigmaPrime = EcpToProto(prover.sigPrime)

	b, err := proto.Marshal(proof)
	if err != nil {
		return nil, err
	}

	ret.NonRevokedProof = b

	return ret, nil
}
