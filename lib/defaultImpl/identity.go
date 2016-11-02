package defaultImpl

import (
	"errors"
	"net/http"

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
)

func newIdentity(client *Client, name string, key []byte, cert []byte) *Identity {
	id := new(Identity)
	id.client = client
	id.Name = name
	id.PublicSigner = newTemporalSigner(key, cert)
	return id
}

// Identity is COP's implementation of an idp.Identity
type Identity struct {
	client       *Client
	Name         string          `json:"name"`
	PublicSigner *TemporalSigner `json:"publicSigner"`
}

// GetName returns the identity name
func (i *Identity) GetName() string {
	return i.Name
}

// GetPublicSigner returns the public signer for this identity
func (i *Identity) GetPublicSigner() idp.TemporalSigner {
	return i.PublicSigner
}

// GetPrivateSigners returns private signers for this identity
func (i *Identity) GetPrivateSigners(req *idp.GetPrivateSignersRequest) ([]idp.TemporalSigner, error) {
	return nil, errors.New("NotImplemented")
}

// GetAttributeNames returns the names of all attributes associated with this identity
func (i *Identity) GetAttributeNames() ([]string, error) {
	return nil, errors.New("NotImplemented")
}

// Delete this identity completely and revoke all of it's signers
func (i *Identity) Delete() error {
	return errors.New("NotImplemented")
}

// Serialize an identity
func (i *Identity) Serialize() []byte {
	// TODO: Implement
	return nil
}

func (i *Identity) post(endpoint string, reqBody interface{}) ([]byte, error) {
	reqBodyBytes, cerr := util.Marshal(reqBody, endpoint)
	if cerr != nil {
		return nil, cerr
	}
	req, err := i.client.newPost(endpoint, reqBodyBytes)
	if err != nil {
		return nil, err
	}
	err = i.addTokenAuthHdr(req, reqBodyBytes)
	if err != nil {
		return nil, err
	}
	return i.client.sendPost(req)
}

func (i *Identity) addTokenAuthHdr(req *http.Request, body []byte) error {
	log.Debug("addTokenAuthHdr begin")
	cert := i.getMyCert()
	key := i.getMyKey() // TODO: Will change for BCCSP since we can't see key
	token, tokenerr := util.CreateToken(cert, key, body)
	if tokenerr != nil {
		log.Debug("addTokenAuthHdr failed: CreateToken")
		return cop.WrapError(tokenerr, 1, "test")
	}
	req.Header.Set("authorization", token)
	log.Debug("addTokenAuthHdr success")
	return nil
}

func (i *Identity) getMyCert() []byte {
	return i.PublicSigner.getMyCert()
}

func (i *Identity) getMyKey() []byte {
	return i.PublicSigner.getMyKey()
}
