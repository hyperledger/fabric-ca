package defaultImpl

import "errors"

func newTemporalSigner(key []byte, cert []byte) *TemporalSigner {
	return &TemporalSigner{newSigner(key, cert)}
}

// TemporalSigner implements idp.TemporalSigner
type TemporalSigner struct {
	Signer
}

// Renew renews the signer's certificate
func (ts *TemporalSigner) Renew() error {
	return errors.New("NotImplemented")
}

// Revoke revokes the signer's certificate
func (ts *TemporalSigner) Revoke() error {
	return errors.New("NotImplemented")
}
