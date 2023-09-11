/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	bccsp "github.com/IBM/idemix/bccsp/types"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	fabric_bccsp "github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

// Issuer is the interface to the Issuer for external components
type Issuer interface {
	Init(renew bool, db db.FabricCADB, levels *dbutil.Levels) error
	IssuerPublicKey() ([]byte, error)
	RevocationPublicKey() ([]byte, error)
	IssueCredential(ctx ServerRequestCtx) (*EnrollmentResponse, error)
	GetCRI(ctx ServerRequestCtx) (*api.GetCRIResponse, error)
	VerifyToken(authHdr, method, uri string, body []byte) (string, error)
}

//go:generate mockery --name ServerRequestCtx --case underscore

//go:generate mockery --name UserUser --case underscore
type UserUser interface {
	user.User
}

// ServerRequestCtx is the server request context that Idemix enroll expects
type ServerRequestCtx interface {
	IsBasicAuth() bool
	BasicAuthentication() (string, error)
	TokenAuthentication() (string, error)
	GetCaller() (user.User, error)
	ReadBody(body interface{}) error
}

type IssuerInst struct {
	Name    string
	HomeDir string
	Cfg     *Config
	Db      db.FabricCADB
	Csp     bccsp.BCCSP
	// The Idemix credential DB accessor
	CredDBAccessor CredDBAccessor
	// idemix issuer credential for the CA
	IssuerCred          IssuerCredential
	RevocationAuthority RevocationAuthority
	NonceManager        NonceManager
	IsInitialized       bool
	mutex               sync.Mutex
}

// NewIssuer returns an object that implements Issuer interface
func NewIssuer(name, homeDir string, config *Config, csp bccsp.BCCSP) Issuer {
	issuer := IssuerInst{Name: name, HomeDir: homeDir, Cfg: config, Csp: csp}
	return &issuer
}

func (i *IssuerInst) Init(renew bool, db db.FabricCADB, levels *dbutil.Levels) error {
	if i.IsInitialized {
		return nil
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	// After obtaining a lock, check again to see if issuer has been initialized by another thread
	if i.IsInitialized {
		return nil
	}

	if db == nil || reflect.ValueOf(db).IsNil() || !db.IsInitialized() {
		log.Debugf("Returning without initializing Idemix issuer for CA '%s' as the database is not initialized", i.Name)
		return nil
	}
	i.Db = db
	err := i.Cfg.init(i.HomeDir)
	if err != nil {
		return err
	}
	err = i.initKeyMaterial(renew)
	if err != nil {
		return err
	}
	i.CredDBAccessor = NewCredentialAccessor(i.Db, levels.Credential)
	log.Debugf("Intializing revocation authority for issuer '%s'", i.Name)
	i.RevocationAuthority, err = NewRevocationAuthority(i, levels.RAInfo)
	if err != nil {
		return err
	}
	log.Debugf("Intializing nonce manager for issuer '%s'", i.Name)
	i.NonceManager, err = NewNonceManager(i, &wallClock{}, levels.Nonce)
	if err != nil {
		return err
	}
	i.IsInitialized = true
	return nil
}

func (i *IssuerInst) IssuerPublicKey() ([]byte, error) {
	if !i.IsInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	isk, err := i.IssuerCred.GetIssuerKey()
	if err != nil {
		return nil, err
	}

	ipk, err := isk.PublicKey()
	if err != nil {
		return nil, err
	}

	ipkBytes, err := ipk.Bytes()
	if err != nil {
		return nil, err
	}
	return ipkBytes, nil
}

func (i *IssuerInst) RevocationPublicKey() ([]byte, error) {
	if !i.IsInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	rpk := i.RevocationAuthority.PublicKey()

	return rpk.Bytes()
}

func (i *IssuerInst) IssueCredential(ctx ServerRequestCtx) (*EnrollmentResponse, error) {
	if !i.IsInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	handler := EnrollRequestHandler{
		Ctx:    ctx,
		Issuer: i,
	}

	return handler.HandleRequest()
}

func (i *IssuerInst) GetCRI(ctx ServerRequestCtx) (*api.GetCRIResponse, error) {
	if !i.IsInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	handler := CRIRequestHandler{
		Ctx:    ctx,
		Issuer: i,
	}

	return handler.HandleRequest()
}

func (i *IssuerInst) VerifyToken(authHdr, method, uri string, body []byte) (string, error) {
	if !i.IsInitialized {
		return "", errors.New("Issuer is not initialized")
	}
	// Disclosure array indicates which attributes are disclosed. 1 means disclosed. Currently four attributes are
	// supported: OU, role, enrollmentID and revocationHandle. Third element of disclosure array is set to 1
	// to indicate that the server expects enrollmentID to be disclosed in the signature sent in the authorization token.
	// EnrollmentID is disclosed to check if the signature was infact created using credential of a user whose
	// enrollment ID is the one specified in the token. So, enrollment ID in the token is used to check if the user
	// is valid and has a credential (by checking the DB) and it is used to verify zero knowledge proof.
	parts := getTokenParts(authHdr)
	if parts == nil {
		return "", errors.New("Invalid Idemix token format; token format must be: 'idemix.<enrollment ID>.<base64 encoding of Idemix signature bytes>'")
	}
	if parts[1] != api.IdemixTokenVersion1 {
		return "", errors.New("Invalid version found in the Idemix token. Version must be 1")
	}
	enrollmentID := parts[2]
	creds, err := i.CredDBAccessor.GetCredentialsByID(enrollmentID)
	if err != nil {
		return "", errors.Errorf("Failed to check if enrollment ID '%s' is valid", enrollmentID)
	}
	if len(creds) == 0 {
		return "", errors.Errorf("Enrollment ID '%s' does not have any Idemix credentials", enrollmentID)
	}
	b64body := util.B64Encode(body)
	b64uri := util.B64Encode([]byte(uri))
	msg := method + "." + b64uri + "." + b64body
	digest, digestError := i.Csp.Hash([]byte(msg), &fabric_bccsp.SHAOpts{})
	if digestError != nil {
		return "", errors.WithMessage(digestError, fmt.Sprintf("Failed to create authentication token '%s'", msg))
	}

	issuerSecretKey, err := i.IssuerCred.GetIssuerKey()
	if err != nil {
		return "", errors.WithMessage(err, "Failed to get issuer key")
	}

	IssuerPublicKey, err := issuerSecretKey.PublicKey()
	if err != nil {
		return "", errors.WithMessage(err, "Failed to get issuer public key")
	}

	ra := i.RevocationAuthority
	epoch, err := ra.Epoch()
	if err != nil {
		return "", err
	}

	sigBytes, err := util.B64Decode(parts[3])
	if err != nil {
		return "", errors.WithMessage(err, "Failed to base64 decode signature specified in the token")
	}

	valid, err := i.Csp.Verify(
		IssuerPublicKey,
		sigBytes,
		digest,
		&bccsp.IdemixSignerOpts{
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte(enrollmentID)},
				{Type: bccsp.IdemixHiddenAttribute},
			},
			RhIndex:          3,
			EidIndex:         2,
			VerificationType: bccsp.BestEffort,
			Epoch:            epoch,
		},
	)
	if err != nil || !valid {
		return "", errors.WithMessage(err, "Failed to verify the token")
	}

	return enrollmentID, nil
}

func (i *IssuerInst) initKeyMaterial(renew bool) error {
	idemixPubKey := i.Cfg.IssuerPublicKeyfile
	idemixSecretKey := i.Cfg.IssuerSecretKeyfile
	issuerCred := NewIssuerCredential(idemixPubKey, idemixSecretKey, i.Csp)

	log.Debugf("renew is set to [%v]", renew)
	if !renew {
		pubKeyFileExists := util.FileExists(idemixPubKey)
		privKeyFileExists := util.FileExists(idemixSecretKey)
		// If they both exist, the CA was already initialized, load the keys from the disk
		log.Debugf("pubKeyFileExists && privKeyFileExists : [%s:%s][%s:%s]", idemixPubKey, pubKeyFileExists, idemixSecretKey, privKeyFileExists)
		if pubKeyFileExists && privKeyFileExists {
			log.Info("The Idemix issuer public and secret key files already exist")
			log.Infof("   secret key file location: %s", idemixSecretKey)
			log.Infof("   public key file location: %s", idemixPubKey)
			err := issuerCred.Load()
			if err != nil {
				return err
			}
			i.IssuerCred = issuerCred
			return nil
		}
	}
	ik, err := issuerCred.NewIssuerKey()
	if err != nil {
		return err
	}
	log.Debugf("Idemix issuer public and secret keys were generated for CA '%s'", i.Name)
	issuerCred.SetIssuerKey(ik)
	err = issuerCred.Store()
	if err != nil {
		return err
	}
	i.IssuerCred = issuerCred
	return nil
}

func getTokenParts(token string) []string {
	parts := strings.Split(token, ".")
	if len(parts) == 4 && parts[0] == "idemix" {
		return parts
	}
	return nil
}

// IsToken returns true if the specified token has the format expected of an authorization token
// that is created using an Idemix credential
func IsToken(token string) bool {
	return getTokenParts(token) != nil
}

type wallClock struct{}

func (wc wallClock) Now() time.Time {
	return time.Now()
}
