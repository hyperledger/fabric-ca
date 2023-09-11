/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	idemix "github.com/IBM/idemix/bccsp"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	"github.com/IBM/idemix/bccsp/types"
	bccsp "github.com/IBM/idemix/bccsp/types"
	ibccsp "github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	dmocks "github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func getIssuer(t *testing.T, testDir string, getranderror, newIssuerKeyerror bool) (*dmocks.DbFabricCADB, Issuer) {
	err := os.MkdirAll(filepath.Join(testDir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}

	db := new(dmocks.DbFabricCADB)

	tx := new(dmocks.DbFabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRAInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	db.On("IsInitialized").Return(true)

	cfg := &Config{
		RHPoolSize:         100,
		NonceExpiration:    "15s",
		NonceSweepInterval: "15m",
	}

	revSK := new(mocks.BccspKey)
	revPK := new(mocks.BccspKey)
	revSK.On("PublicKey").Return(revPK, nil)
	revSK.On("Bytes").Return([]byte("revSK_Bytes"), nil)
	revPK.On("Bytes").Return([]byte("revPK_Bytes"), nil)
	isk := new(mocks.BccspKey)
	ipk := new(mocks.BccspKey)
	isk.On("PublicKey").Return(ipk, nil)
	isk.On("Bytes").Return([]byte("isk_Bytes"), nil)
	ipk.On("Bytes").Return([]byte("ipk_Bytes"), nil)

	mockCsp := new(mocks.BccspBCCSP)
	mockCsp.On("KeyGen", &types.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: []string{"OU", "Role", "EnrollmentID", "RevocationHandle"}}).
		Return(isk, nil)

	var issuer Issuer
	if !getranderror && !newIssuerKeyerror {
		issuer = NewIssuer("ca1", testDir, cfg, getCSP(t))
	} else {
		if newIssuerKeyerror {
			mockCsp.On("KeyGen", &types.IdemixRevocationKeyGenOpts{Temporary: true}).Return(nil, errors.New("error error"))
		} else {
			mockCsp.On("KeyGen", &types.IdemixRevocationKeyGenOpts{Temporary: true}).Return(revSK, nil)
		}
		issuer = NewIssuer("ca1", testDir, cfg, mockCsp)
	}

	f := getSelectFunc(t, true, false)

	rcInfosForSelect := []RevocationAuthorityInfo{}
	db.On("Select", "GetRAInfo", &rcInfosForSelect, SelectRAInfo).Return(f)
	rcinfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.SqlResult)
	result.On("RowsAffected").Return(int64(1), nil)
	db.On("NamedExec", "AddRAInfo", InsertRAInfo, &rcinfo).Return(result, nil)

	return db, issuer
}

func getCredsSelectFunc(t *testing.T, creds *[]CredRecord, isAppend bool) func(string, interface{}, string, ...interface{}) error {
	return func(funcName string, dest interface{}, query string, args ...interface{}) error {
		credRecs := dest.(*[]CredRecord)
		cred := CredRecord{
			ID:     "foo",
			Status: "active",
			Cred:   "",
		}

		if isAppend {
			//*creds = append(*creds, cred)
			*credRecs = append(*credRecs, cred)
		}
		return nil
	}
}

func generatePublicPrivateKeyPair(t *testing.T) (string, string, string, error) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), strings.Replace(t.Name(), "/", "-", -1))
	assert.NoError(t, err)

	testPublicKeyFile := filepath.Join(tmpDir, "IdemixPublicKey")
	testSecretKeyFile := filepath.Join(tmpDir, "IdemixSecretKey")

	pk, sk := makePubPrivKeyPair(t)
	err = ioutil.WriteFile(testPublicKeyFile, pk, 0o644)
	if err != nil {
		t.Fatalf("Failed writing public key to file: %s", err.Error())
	}

	err = ioutil.WriteFile(testSecretKeyFile, sk, 0o644)
	if err != nil {
		t.Fatalf("Failed writing private key to file: %s", err.Error())
	}
	return testPublicKeyFile, testSecretKeyFile, tmpDir, err
}

func makePubPrivKeyPair(t *testing.T) ([]byte, []byte) {
	attrs := []string{AttrOU, AttrRole, AttrEnrollmentID, AttrRevocationHandle}

	IssuerSecretKey, err := getCSP(t).KeyGen(&bccsp.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: attrs})
	assert.NoError(t, err)

	IssuerPublicKey, err := IssuerSecretKey.PublicKey()
	assert.NoError(t, err)

	iskBytes, err := IssuerSecretKey.Bytes()
	assert.NoError(t, err)

	ipkBytes, err := IssuerPublicKey.Bytes()
	assert.NoError(t, err)

	return ipkBytes, iskBytes
}

func GeneratePublicPrivateKeyPair(t *testing.T) (string, string, string, error) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), strings.Replace(t.Name(), "/", "-", -1))
	assert.NoError(t, err)

	testPublicKeyFile := filepath.Join(tmpDir, "IdemixPublicKey")
	testSecretKeyFile := filepath.Join(tmpDir, "IdemixSecretKey")

	pk, sk := makeIssuerKeypair(getCSP(t), t)
	err = ioutil.WriteFile(testPublicKeyFile, pk, 0o644)
	if err != nil {
		t.Fatalf("Failed writing public key to file: %s", err.Error())
	}

	err = ioutil.WriteFile(testSecretKeyFile, sk, 0o644)
	if err != nil {
		t.Fatalf("Failed writing private key to file: %s", err.Error())
	}
	return testPublicKeyFile, testSecretKeyFile, tmpDir, err
}

// NewDummyKeyStore instantiate a dummy key store
// that neither loads nor stores keys
func NewDummyKeyStore() bccsp.KeyStore {
	return &dummyKeyStore{}
}

// dummyKeyStore is a read-only KeyStore that neither loads nor stores keys.
type dummyKeyStore struct {
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ks *dummyKeyStore) ReadOnly() bool {
	return true
}

// GetKey returns a key object whose SKI is the one passed.
func (ks *dummyKeyStore) GetKey(ski []byte) (bccsp.Key, error) {
	return nil, errors.New("Key not found. This is a dummy KeyStore")
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
func (ks *dummyKeyStore) StoreKey(k bccsp.Key) error {
	return errors.New("Cannot store key. This is a dummy read-only KeyStore")
}

func makeIssuerKeypair(CSP bccsp.BCCSP, t *testing.T) ([]byte, []byte) {
	attrs := []string{AttrOU, AttrRole, AttrEnrollmentID, AttrRevocationHandle}

	IssuerSecretKey, err := CSP.KeyGen(&bccsp.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: attrs})
	assert.NoError(t, err)
	IssuerPublicKey, err := IssuerSecretKey.PublicKey()
	assert.NoError(t, err)

	IssuerSecretKeyBytes, err := IssuerSecretKey.Bytes()
	assert.NoError(t, err)

	IssuerPublicKeyBytes, err := IssuerPublicKey.Bytes()
	assert.NoError(t, err)

	return IssuerPublicKeyBytes, IssuerSecretKeyBytes
}

func getCSP(t *testing.T) bccsp.BCCSP {
	curve := math.Curves[math.BLS12_381_BBS]
	translator := &amcl.Gurvy{C: curve}

	CSP, err := idemix.New(NewDummyKeyStore(), curve, translator, true)
	assert.NoError(t, err)

	return CSP
}

func getCredSelectFunc(t *testing.T, isError bool) func(string, interface{}, string, ...interface{}) error {
	return func(funcName string, dest interface{}, query string, args ...interface{}) error {
		crs := dest.(*[]CredRecord)
		cr := getCredRecord()
		*crs = append(*crs, cr)
		if isError {
			return errors.New("Failed to get credentials from DB")
		}
		return nil
	}
}

func getCredRecord() CredRecord {
	return CredRecord{
		ID:               "foo",
		CALabel:          "",
		Expiry:           time.Now(),
		Level:            1,
		Reason:           0,
		Status:           "good",
		RevocationHandle: "1",
		Cred:             "blah",
	}
}

func createCRI(t *testing.T) ([]byte, error) {
	RevocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)

	cri, err := getCSP(t).Sign(
		RevocationKey,
		nil,
		&bccsp.IdemixCRISignerOpts{},
	)
	assert.NoError(t, err)

	return cri, nil
}

func getB64EncodedCred(cred []byte) (string, error) {
	b64CredBytes := util.B64Encode(cred)
	return b64CredBytes, nil
}

func getReadBodyFunc(t *testing.T, credReq, nonce []byte) func(body interface{}) error {
	return func(body interface{}) error {
		enrollReq, _ := body.(*api.IdemixEnrollmentRequestNet)
		if credReq == nil {
			return errors.New("Error reading the body")
		}
		enrollReq.CredRequest = credReq
		enrollReq.IssuerNonce = nonce
		return nil
	}
}

func newIdemixCredentialRequest(t *testing.T, nonce []byte, testPublicKeyFile, testSecretKeyFile string) ([]byte, ibccsp.Key) {
	csp := getCSP(t)

	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, csp)
	err := issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}

	isk, err := issuerCred.GetIssuerKey()
	if err != nil {
		t.Fatalf("Issuer credential returned error while getting issuer key")
	}

	ipk, err := isk.PublicKey()
	assert.NoError(t, err)

	UserKey, err := csp.KeyGen(&types.IdemixUserSecretKeyGenOpts{Temporary: true})
	assert.NoError(t, err)

	credRequest, err := csp.Sign(
		UserKey,
		nil,
		&bccsp.IdemixCredentialRequestSignerOpts{IssuerPK: ipk, IssuerNonce: nonce},
	)
	assert.NoError(t, err)

	return credRequest, UserKey
}
