/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/lib"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	dmocks "github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/kisielk/sqlstruct"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewIssuer(t *testing.T) {
	cfg := &Config{
		NonceExpiration:    "15",
		NonceSweepInterval: "15",
	}
	issuer := NewIssuer("ca1", ".", cfg, getCSP(t))
	assert.NotNil(t, issuer)
}

func TestInit(t *testing.T) {
	testdir := t.TempDir()
	err := os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}

	db, issuer := getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)
	err = issuer.Init(false, nil, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err, "Init should not return an error if db is nil")

	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)

	ik, err := issuer.IssuerPublicKey()
	assert.NoError(t, err, "IssuerPublicKey should not return an error")
	assert.NotNil(t, ik)
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("IsBasicAuth").Return(true)
	ctx.On("BasicAuthentication").Return("", errors.New("Authentication error"))
	ctx.On("TokenAuthentication").Return("", errors.New("Authentication error"))
	_, err = issuer.IssueCredential(ctx)
	assert.Error(t, err, "IssuerCredential should fail")
	_, err = issuer.GetCRI(ctx)
	assert.Error(t, err, "GetCRI should fail")
}

func TestInitDBNotInitialized(t *testing.T) {
	cfg := &Config{
		NonceExpiration:    "15s",
		NonceSweepInterval: "15m",
	}
	var db *dmocks.DbFabricCADB
	issuer := NewIssuer("ca1", ".", cfg, getCSP(t))
	err := issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)

	db = new(dmocks.DbFabricCADB)
	db.On("IsInitialized").Return(false)
	issuer = NewIssuer("ca1", ".", cfg, getCSP(t))
	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)
}

func TestInitExistingIssuerCredential(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	err = lib.CopyFile(testPublicKeyFile, filepath.Join(testdir, "IssuerPublicKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}
	err = lib.CopyFile(testSecretKeyFile, filepath.Join(testdir, "msp/keystore/IssuerSecretKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}

	db, issuer := getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)

	secrekeyfile := filepath.Join(testdir, "msp/keystore/IssuerSecretKey")
	secrekeyFileInfo, err := os.Stat(secrekeyfile)
	if err != nil {
		t.Fatalf("os.Stat failed on test dir: %s", err)
	}
	oldmode := secrekeyFileInfo.Mode()
	err = os.Chmod(secrekeyfile, 0o000)
	if err != nil {
		t.Fatalf("Chmod on %s failed: %s", secrekeyFileInfo.Name(), err)
	}
	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.Error(t, err, "Init should fail if it fails to load issuer credential")

	err = os.Chmod(secrekeyfile, oldmode)
	if err != nil {
		t.Fatalf("Chmod on %s failed: %s", testdir, err)
	}
	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)
}

func TestInitRenewTrue(t *testing.T) {
	testdir := t.TempDir()
	db, issuer := getIssuer(t, testdir, true, false)
	assert.NotNil(t, issuer)

	db, issuer = getIssuer(t, testdir, false, true)
	assert.NotNil(t, issuer)
	err := issuer.Init(true, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.Error(t, err, "Init should fail if it fails to create new issuer key")

	db, issuer = getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)

	testdataInfo, err := os.Stat(testdir)
	if err != nil {
		t.Fatalf("os.Stat failed on test dir: %s", err)
	}
	oldmode := testdataInfo.Mode()
	err = os.Chmod(testdir, 0o000)
	if err != nil {
		t.Fatalf("Chmod on %s failed: %s", testdataInfo.Name(), err)
	}
	defer func() {
		err = os.Chmod(testdir, oldmode)
		if err != nil {
			t.Fatalf("Chmod on %s failed: %s", testdir, err)
		}
	}()
	err = issuer.Init(true, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.Error(t, err, "Init should fail if it fails to store issuer credential")
}

func TestVerifyTokenError(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()

	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	err = lib.CopyFile(testPublicKeyFile, filepath.Join(testdir, "IssuerPublicKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}
	err = lib.CopyFile(testSecretKeyFile, filepath.Join(testdir, "msp/keystore/IssuerSecretKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}

	db, issuer := getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)

	_, err = issuer.VerifyToken("idemix.1.foo.blah", "", "", []byte{})
	assert.Error(t, err, "VerifyToken should fail as issuer is not initialized")

	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)

	_, err = issuer.VerifyToken("idemix.1.foo", "", "", []byte{})
	assert.Error(t, err, "VerifyToken should fail if the auth header does not have four parts separated by '.'")

	_, err = issuer.VerifyToken("idemix.2.foo.bar", "", "", []byte{})
	assert.Error(t, err, "VerifyToken should fail if the auth header does not have correct version")

	db.On("Rebind", SelectCredentialByIDSQL).Return(SelectCredentialByIDSQL)
	credRecords := []CredRecord{}
	sqlstr := fmt.Sprintf(SelectCredentialByIDSQL, sqlstruct.Columns(CredRecord{}))
	db.On("Select", "GetCredentialsByID", &credRecords, sqlstr, "foo").Return(errors.New("db error getting creds for user"))

	_, err = issuer.VerifyToken("idemix.1.foo.sig", "", "", []byte{})
	assert.Error(t, err, "VerifyToken should fail if there is error looking up enrollment id in the database")
}

func TestVerifyTokenNoCreds(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	err = lib.CopyFile(testPublicKeyFile, filepath.Join(testdir, "IssuerPublicKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}
	err = lib.CopyFile(testSecretKeyFile, filepath.Join(testdir, "msp/keystore/IssuerSecretKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}

	db, issuer := getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)

	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)

	db.On("Rebind", SelectCredentialByIDSQL).Return(SelectCredentialByIDSQL)
	credRecords := []CredRecord{}
	sqlstr := fmt.Sprintf(SelectCredentialByIDSQL, sqlstruct.Columns(CredRecord{}))
	f := getCredsSelectFunc(t, &credRecords, false)
	db.On("Select", "GetCredentialsByID", &credRecords, sqlstr, "foo").Return(f)

	_, err = issuer.VerifyToken("idemix.1.foo.sig", "", "", []byte{})
	assert.Error(t, err, "VerifyToken should fail if the enrollment id does not have creds")
}

func TestVerifyTokenBadSignatureEncoding(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	err = lib.CopyFile(testPublicKeyFile, filepath.Join(testdir, "IssuerPublicKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}
	err = lib.CopyFile(testSecretKeyFile, filepath.Join(testdir, "msp/keystore/IssuerSecretKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}

	db, issuer := getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)

	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)

	db.On("Rebind", SelectCredentialByIDSQL).Return(SelectCredentialByIDSQL)
	credRecords := []CredRecord{}
	sqlstr := fmt.Sprintf(SelectCredentialByIDSQL, sqlstruct.Columns(CredRecord{}))
	f := getCredsSelectFunc(t, &credRecords, true)
	db.On("Select", "GetCredentialsByID", &credRecords, sqlstr, "foo").Return(f)

	_, err = issuer.VerifyToken("idemix.1.foo.sig", "", "", []byte{})
	assert.Error(t, err, "VerifyToken should fail if the signature is not in base64 format")
	assert.NotEqual(t, err.Error(), "errer")
}

func TestVerifyTokenBadSignature(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	err = lib.CopyFile(testPublicKeyFile, filepath.Join(testdir, "IssuerPublicKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}
	err = lib.CopyFile(testSecretKeyFile, filepath.Join(testdir, "msp/keystore/IssuerSecretKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}

	db, issuer := getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)

	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)

	db.On("Rebind", SelectCredentialByIDSQL).Return(SelectCredentialByIDSQL)
	credRecords := []CredRecord{}
	sqlstr := fmt.Sprintf(SelectCredentialByIDSQL, sqlstruct.Columns(CredRecord{}))
	f := getCredsSelectFunc(t, &credRecords, true)
	db.On("Select", "GetCredentialsByID", &credRecords, sqlstr, "admin").Return(f)

	sig := util.B64Encode([]byte("hello"))
	_, err = issuer.VerifyToken("idemix.1.admin."+sig, "", "", []byte{})
	assert.Error(t, err, "VerifyToken should fail if the signature is not valid")

	digest, err := util.GetDefaultBCCSP().Hash([]byte(sig), &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed to get hash of the message: %s", err.Error())
	}
	_, err = issuer.VerifyToken("idemix.1.admin.CkQKIAoanxNH9nO5ivQy94e+DH+SiwkkBhYeNbtyQhM1HD7FEiBbBcMVcCW9HoJe5KWMtyvO6a4UtB4xo2x/SV7xvxcVvBJECiBugYjF0AZ8lWvaeKCXtEbPvawQye7RK0m5SpQzEwcu/RIgioEuVacQR5DroKwgAZi3ALClpCLJFjlRwVv7w2zJcQQaRAogeAU3ZnfcA60kGIm6gHKGTRrI3O9sbkpdHt/UIF+Tz5sSIHGfTP5B7Ocb43q3sewpuqIjDyvFEzIeBpummJD4MPB5IiAewOhliKfwXta7pSCIMlfKqmuJbhAwhJl7vJdhfEW05iogGY6MfvsdO+HvQdSmlIexEBgl51KsFCO6MrAZbms/hLAyIHbqzC8f7sliJ6Hzn65JZKUyHXiAnOM3iydZ7gntoYXxOiClzG32BL3M4MyQGHz6SP8Aozxh3u0dATr0uxOOI6p94EIgO90ealPZ51ZXP+JsAWwLePpyX+lgegF0Gp002uFyv0tKIFRSBfhnRqm7Dk1VbG1hSsl7AJU8nzzYZJZKHRFrhdvGUiCWUu3nvjr5TEFtF5eOMp5XTPXmUNTq8k3SLckY1o35mlIgOeJtkxDc7NtKAiF+cz+cIsv1MIQ3qGXj0nwoMjnHvMJSIALGJWjFKVhK9B9P8BOkO03iMwzNJJdSeA8MIRGyk5WCWiCGix0AHQA29jHVOCaCrBZUVlqBRLa5Kzpftk0jp3LKXmJECiDheCgd36mEjsr1D4Sm+cbtE3XKAdRI2dLq5bFQZqN4/RIgNbxez4+fxVsRuGu8ooFkfem2C5/+1z3QDzyu8fu3fyVqID34eII73Km/SviYxAoHZ91HXIHXhGwid4DFO+xuGI7ycogBCiD+DDNQtMlsIChWD1d8KJE6zhxTmhK/hDzSJha2icCe+xIgTqZgV3OKwFTbWuHGN9gTuSTdeOKH0DWJ0mntNKN+aisaIHAgRufFQqOzdncNdRJOPlHvyyR1jWFYSOkJtIG+3Cf/IiAFVOO804jCkELupkkpfrKfi0y+gIIamLPgEoERSq0Em3pgkd4c0QZIUDeyRVBgwDj7aTk8J+xzdGZSCgIt8RpuKoxmfuDV2SlFfw/fVZqfPH02+jYeyqxbf7FD8vo5dstEpLHy86Yno6zr1bXLDLe34r2XIIH6KrYFI3gYAsQhzzd/gAEBigEA", "", "", digest)
	assert.Error(t, err, "VerifyToken should fail signature is valid but verification fails")
}

func TestIsToken(t *testing.T) {
	token := "idemixx.1.foo.blah"
	assert.False(t, IsToken(token))
	token = "foo.sig"
	assert.False(t, IsToken(token))
	token = "idemix.1.foo.sig"
	assert.True(t, IsToken(token))
}

func TestRevocationPublicKey(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	err = lib.CopyFile(testPublicKeyFile, filepath.Join(testdir, "IssuerPublicKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}
	err = lib.CopyFile(testSecretKeyFile, filepath.Join(testdir, "msp/keystore/IssuerSecretKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}

	db, issuer := getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)

	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err, "Init should not return an error")

	_, err = issuer.RevocationPublicKey()
	assert.NoError(t, err, "RevocationPublicKey should not return an error")
}
