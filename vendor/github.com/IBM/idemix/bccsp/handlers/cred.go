/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package handlers

import (
	"github.com/IBM/idemix/bccsp/types"
	bccsp "github.com/IBM/idemix/bccsp/types"
	"github.com/pkg/errors"
)

// CredentialRequestSigner produces credential requests
type CredentialRequestSigner struct {
	// CredRequest implements the underlying cryptographic algorithms
	CredRequest types.CredRequest
}

func (c *CredentialRequestSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	userSecretKey, ok := k.(*UserSecretKey)
	if !ok {
		return nil, errors.New("invalid key, expected *userSecretKey")
	}
	credentialRequestSignerOpts, ok := opts.(*bccsp.IdemixCredentialRequestSignerOpts)
	if !ok {
		return nil, errors.New("invalid options, expected *IdemixCredentialRequestSignerOpts")
	}
	if credentialRequestSignerOpts.IssuerPK == nil {
		return nil, errors.New("invalid options, missing issuer public key")
	}
	issuerPK, ok := credentialRequestSignerOpts.IssuerPK.(*issuerPublicKey)
	if !ok {
		return nil, errors.New("invalid options, expected IssuerPK as *issuerPublicKey")
	}

	return c.CredRequest.Sign(userSecretKey.Sk, issuerPK.pk, credentialRequestSignerOpts.IssuerNonce)
}

type BlindCredentialRequestSigner struct {
	CredRequest types.BlindCredRequest
}

func (c *BlindCredentialRequestSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	userSecretKey, ok := k.(*UserSecretKey)
	if !ok {
		return nil, errors.New("invalid key, expected *userSecretKey")
	}
	credentialRequestSignerOpts, ok := opts.(*bccsp.IdemixBlindCredentialRequestSignerOpts)
	if !ok {
		return nil, errors.New("invalid options, expected *IdemixCredentialRequestSignerOpts")
	}
	if credentialRequestSignerOpts.IssuerPK == nil {
		return nil, errors.New("invalid options, missing issuer public key")
	}
	issuerPK, ok := credentialRequestSignerOpts.IssuerPK.(*issuerPublicKey)
	if !ok {
		return nil, errors.New("invalid options, expected IssuerPK as *issuerPublicKey")
	}

	cred, blinding, err := c.CredRequest.Blind(userSecretKey.Sk, issuerPK.pk, credentialRequestSignerOpts.IssuerNonce)
	if err != nil {
		return nil, err
	}

	credentialRequestSignerOpts.Blinding = blinding

	return cred, err
}

// CredentialRequestVerifier verifies credential requests
type CredentialRequestVerifier struct {
	// CredRequest implements the underlying cryptographic algorithms
	CredRequest types.CredRequest
}

func (c *CredentialRequestVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	issuerPublicKey, ok := k.(*issuerPublicKey)
	if !ok {
		return false, errors.New("invalid key, expected *issuerPublicKey")
	}
	credentialRequestSignerOpts, ok := opts.(*bccsp.IdemixCredentialRequestSignerOpts)
	if !ok {
		return false, errors.New("invalid options, expected *IdemixCredentialRequestSignerOpts")
	}

	err := c.CredRequest.Verify(signature, issuerPublicKey.pk, credentialRequestSignerOpts.IssuerNonce)
	if err != nil {
		return false, err
	}

	return true, nil
}

type BlindCredentialRequestVerifier struct {
	CredRequest types.BlindCredRequest
}

func (c *BlindCredentialRequestVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	issuerPublicKey, ok := k.(*issuerPublicKey)
	if !ok {
		return false, errors.New("invalid key, expected *issuerPublicKey")
	}
	credentialRequestSignerOpts, ok := opts.(*bccsp.IdemixBlindCredentialRequestSignerOpts)
	if !ok {
		return false, errors.New("invalid options, expected *IdemixCredentialRequestSignerOpts")
	}

	err := c.CredRequest.BlindVerify(signature, issuerPublicKey.pk, credentialRequestSignerOpts.IssuerNonce)
	if err != nil {
		return false, err
	}

	return true, nil
}

type CredentialSigner struct {
	Credential types.Credential
}

func (s *CredentialSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	issuerSecretKey, ok := k.(*issuerSecretKey)
	if !ok {
		return nil, errors.New("invalid key, expected *issuerSecretKey")
	}
	credOpts, ok := opts.(*bccsp.IdemixCredentialSignerOpts)
	if !ok {
		return nil, errors.New("invalid options, expected *IdemixCredentialSignerOpts")
	}

	signature, err = s.Credential.Sign(issuerSecretKey.sk, digest, credOpts.Attributes)
	if err != nil {
		return nil, err
	}

	return
}

type CredentialVerifier struct {
	Credential types.Credential
}

func (v *CredentialVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	userSecretKey, ok := k.(*UserSecretKey)
	if !ok {
		return false, errors.New("invalid key, expected *userSecretKey")
	}
	credOpts, ok := opts.(*bccsp.IdemixCredentialSignerOpts)
	if !ok {
		return false, errors.New("invalid options, expected *IdemixCredentialSignerOpts")
	}
	if credOpts.IssuerPK == nil {
		return false, errors.New("invalid options, missing issuer public key")
	}
	ipk, ok := credOpts.IssuerPK.(*issuerPublicKey)
	if !ok {
		return false, errors.New("invalid issuer public key, expected *issuerPublicKey")
	}
	if len(signature) == 0 {
		return false, errors.New("invalid signature, it must not be empty")
	}

	err = v.Credential.Verify(userSecretKey.Sk, ipk.pk, signature, credOpts.Attributes)
	if err != nil {
		return false, err
	}

	return true, nil
}
