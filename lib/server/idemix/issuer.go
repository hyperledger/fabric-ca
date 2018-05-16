/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"reflect"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// Issuer is the interface to the Issuer for external components
type Issuer interface {
	Init(renew bool, db dbutil.FabricCADB, levels *dbutil.Levels) error
	IssuerPublicKey() ([]byte, error)
	IssueCredential(ctx ServerRequestCtx) (*EnrollmentResponse, error)
	GetCRI(ctx ServerRequestCtx) (*api.GetCRIResponse, error)
}

// MyIssuer provides functions for accessing issuer components
type MyIssuer interface {
	Name() string
	Config() *Config
	IdemixLib() Lib
	DB() dbutil.FabricCADB
	IdemixRand() *amcl.RAND
	IssuerCredential() IssuerCredential
	RevocationAuthority() RevocationAuthority
	NonceManager() NonceManager
	CredDBAccessor() CredDBAccessor
}

// ServerRequestCtx is the server request context that Idemix enroll expects
type ServerRequestCtx interface {
	IsBasicAuth() bool
	BasicAuthentication() (string, error)
	TokenAuthentication() (string, error)
	GetCaller() (spi.User, error)
	ReadBody(body interface{}) error
}

type issuer struct {
	name      string
	homeDir   string
	cfg       *Config
	idemixLib Lib
	db        dbutil.FabricCADB
	// The Idemix credential DB accessor
	credDBAccessor CredDBAccessor
	// idemix issuer credential for the CA
	issuerCred IssuerCredential
	// A random number used in generation of Idemix nonces and credentials
	idemixRand    *amcl.RAND
	rc            RevocationAuthority
	nm            NonceManager
	isInitialized bool
	mutex         sync.Mutex
}

// NewIssuer returns an object that implements Issuer interface
func NewIssuer(name, homeDir string, config *Config, idemixLib Lib) Issuer {
	issuer := issuer{name: name, homeDir: homeDir, cfg: config, idemixLib: idemixLib}
	return &issuer
}

func (i *issuer) Init(renew bool, db dbutil.FabricCADB, levels *dbutil.Levels) error {

	if i.isInitialized {
		return nil
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	// After obtaining a lock, check again to see if issuer has been initialized by another thread
	if i.isInitialized {
		return nil
	}

	if db == nil || reflect.ValueOf(db).IsNil() || !db.IsInitialized() {
		log.Debugf("Returning without initializing Issuer for CA '%s' as the database is not initialized", i.Name())
		return nil
	}
	i.db = db
	err := i.cfg.init(i.homeDir)
	if err != nil {
		return err
	}
	err = i.initKeyMaterial(renew)
	if err != nil {
		return err
	}
	i.credDBAccessor = NewCredentialAccessor(i.db, levels.Credential)
	log.Debugf("Intializing revocation authority for issuer %s", i.Name())
	i.rc, err = NewRevocationAuthority(i, levels.RAInfo)
	if err != nil {
		return err
	}
	log.Debugf("Intializing nonce manager for issuer %s", i.Name())
	i.nm, err = NewNonceManager(i, &wallClock{}, levels.Nonce)
	if err != nil {
		return err
	}
	i.isInitialized = true
	return nil
}

func (i *issuer) IssuerPublicKey() ([]byte, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	ik, err := i.issuerCred.GetIssuerKey()
	if err != nil {
		return nil, err
	}
	ipkBytes, err := proto.Marshal(ik.IPk)
	if err != nil {
		return nil, err
	}
	return ipkBytes, nil
}

func (i *issuer) IssueCredential(ctx ServerRequestCtx) (*EnrollmentResponse, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	handler := EnrollRequestHandler{
		Ctx:     ctx,
		Issuer:  i,
		IdmxLib: i.idemixLib,
	}

	return handler.HandleRequest()
}

func (i *issuer) GetCRI(ctx ServerRequestCtx) (*api.GetCRIResponse, error) {
	if !i.isInitialized {
		return nil, errors.New("Issuer is not initialized")
	}
	handler := CRIRequestHandler{
		Ctx:    ctx,
		Issuer: i,
	}

	return handler.HandleRequest()
}

// Name returns the name of the issuer
func (i *issuer) Name() string {
	return i.name
}

// Config returns config of this issuer
func (i *issuer) Config() *Config {
	return i.cfg
}

// IdemixLib return idemix library instance
func (i *issuer) IdemixLib() Lib {
	return i.idemixLib
}

// DB returns the FabricCADB object (which represents database handle
// to the CA database) associated with this issuer
func (i *issuer) DB() dbutil.FabricCADB {
	return i.db
}

// IdemixRand returns random number used by this issuer in generation of nonces
// and Idemix credentials
func (i *issuer) IdemixRand() *amcl.RAND {
	return i.idemixRand
}

// IssuerCredential returns IssuerCredential of this issuer
func (i *issuer) IssuerCredential() IssuerCredential {
	return i.issuerCred
}

// RevocationAuthority returns revocation authority of this issuer
func (i *issuer) RevocationAuthority() RevocationAuthority {
	return i.rc
}

// NonceManager returns nonce manager of this issuer
func (i *issuer) NonceManager() NonceManager {
	return i.nm
}

// CredDBAccessor returns the Idemix credential DB accessor for issuer
func (i *issuer) CredDBAccessor() CredDBAccessor {
	return i.credDBAccessor
}

func (i *issuer) initKeyMaterial(renew bool) error {
	log.Debug("Initialize Idemix key material")

	rng, err := i.idemixLib.GetRand()
	if err != nil {
		return errors.Wrapf(err, "Error generating random number")
	}
	i.idemixRand = rng

	idemixPubKey := i.cfg.IssuerPublicKeyfile
	idemixSecretKey := i.cfg.IssuerSecretKeyfile
	issuerCred := NewIssuerCredential(idemixPubKey, idemixSecretKey, i.idemixLib)

	if !renew {
		pubKeyFileExists := util.FileExists(idemixPubKey)
		privKeyFileExists := util.FileExists(idemixSecretKey)
		// If they both exist, the CA was already initialized, load the keys from the disk
		if pubKeyFileExists && privKeyFileExists {
			log.Info("The Idemix issuer public and secret key files already exist")
			log.Infof("   secret key file location: %s", idemixSecretKey)
			log.Infof("   public key file location: %s", idemixPubKey)
			err := issuerCred.Load()
			if err != nil {
				return err
			}
			i.issuerCred = issuerCred
			return nil
		}
	}
	ik, err := issuerCred.NewIssuerKey()
	if err != nil {
		return err
	}
	log.Infof("The Idemix public and secret keys were generated for Issuer %s", i.name)
	issuerCred.SetIssuerKey(ik)
	err = issuerCred.Store()
	if err != nil {
		return err
	}
	i.issuerCred = issuerCred
	return nil
}

type wallClock struct{}

func (wc wallClock) Now() time.Time {
	return time.Now()
}
