// Certificate Authority APIs for Hyperledger Fabric

package ca

// GetInstance returns the default CA provider
// @param config The config data for the CA
func GetDefaultInstance(config string) CA {
	return nil
}

// CA is the Certificate Authority interface
type CA interface {

	// Capabilities returns the capabilities of this CA
	Capabilities() []Capability

	// Register a new member
	// @param req The registration request
	RegisterMember(req *RegistrationRequest) (*RegistrationResponse, error)

	// Enroll a new member
	// @param req The enrollment request
	EnrollMember(req EnrollmentRequest) (Member, error)

	// RegisterAndEnroll registers and enrolls a new identity
	// @param req The registration request
	RegisterAndEnrollMember(req *RegistrationRequest) (Member, error)

	// GetEnrolledMember returns an already enrolled member,
	// or nil if an enrolled member with this name was not found.
	// @param name The enrollment name
	GetEnrolledMember(name string) (Member, error)

	// ImportMember imports a member.
	// @param req The import request
	ImportMember(req *ImportRequest) (Member, error)

	// GetMemberFromBytes deserializes a member from bytes
	GetMemberFromBytes([]byte) (Member, error)

	// GetIdentityFromBytes deserializes an identity from bytes
	GetIdentityFromBytes([]byte) (Identity, error)
}

// Member is a member
type Member interface {

	// Name returns the member name
	Name() string

	// GetPublicIdentity returns the enrollment identity of this member
	GetPublicIdentity() Identity

	// GetPrivateIdentities returns other identities for use by this member
	GetPrivateIdentities(count int, specs *IdentitySpec) ([]Identity, error)

	// GetAttributeNames returns the names of all attributes associated with this member
	GetAttributeNames() ([]string, error)

	// Delete this member completely and all non-expired identities associated with this member
	Delete() error

	// ToBytes converts a member to bytes
	ToBytes() []byte
}

// Identity
type Identity interface {

	// Validate myself
	Validate() error

	// Verify a signature over some message
	Verify(msg []byte, sig []byte) error

	// Verify a signature over some message
	VerifyOpts(msg []byte, sig []byte, opts *SignatureOpts) error

	// VerifyAttributes verifies attributes given proofs
	VerifyAttributes(proof [][]byte, spec *AttributeProofSpec) error

	// ToBytes converts a member to bytes
	ToBytes() []byte
}

// SigningIdentity
type SigningIdentity interface {

	// Extends Identity
	Identity

	// Sign the message
	Sign(msg []byte) ([]byte, error)

	// SignOpts the message with options
	SignOpts(msg []byte, opts *SignatureOpts) ([]byte, error)

	// NewAttributeProof creates a proof for an attribute
	NewAttributeProof(spec *AttributeProofSpec) (proof []byte, err error)

	// Renew this identity
	Renew() error

	// Revoke this identity
	Revoke() error
}

// RegistrationRequest for a new identity
type RegistrationRequest struct {
	// Name is the unique name of the identity
	Name string `json:"id"`
	// Type of identity being registered (e.g. "peer, app, user")
	Type string `json:"type"`
	// Group name associated with the identity
	Group string `json:"group"`
	// Attributes associated with this identity
	Attributes []Attribute `json:"attrs,omitempty"`
	// Registrar is the member that is performing the registration
	Registrar Member `json:"registrar"`
}

// RegistrationResponse is a registration response
type RegistrationResponse struct {
	// The optional secret returned from a registration response
	Secret string `json:"credential,omitempty"`
}

// EnrollmentRequest is a request to enroll a member
type EnrollmentRequest struct {
	// The identity name to enroll
	Name string `json:"name"`
	// The secret returned via Register
	Secret string `json:"secret,omitempty"`
	// The attributes to include in the enrollment certificate (optional)
	Attributes []Attribute `json:"attrs,omitempty"`
}

// EnrollmentResponse is the enrollment response
type EnrollmentResponse struct {
	// The enrollment certificate
	Cert []byte `json:"cert"`
}

// ImportRequest is data required when importing an identity from another CA
type ImportRequest struct {
	// The identity name to import
	Name string `json:"name"`
	// The certificate to import
	Cert []byte `json:"cert"`
	// The private key to import (optional)
	Key []byte `json:"key,omitempty"`
}

type IdentitySpec struct {
	Signer     bool     `json:"signer"`
	Anonymous  bool     `json:"anonymous"`
	Unlinkable bool     `json:"unlinkable"`
	Attrs      []string `json:"attrs"`
	ID         Identity `json:"id"`
}

type SignatureOpts struct {
	Policy []string
	Label  string
}

// Attribute is an arbitrary name/value pair
type Attribute struct {
	Name  string   `json:"name"`
	Value []string `json:"value"`
}

type AttributeProofSpec struct {
	Attributes []string
	Message    []byte
}

// Capability is a capability of a CA
type Capability int

// The capabilities of a CA relative to the CA API
const (
	REGISTRATION  Capability = iota // CA has registrar capability
	ENROLLMENT                      // CA has enrollment capability
	ATTRIBUTES                      // CA has attributes capability
	ANONYMITY                       // CA support anonymous identities
	UNLINKABILITY                   // CA support unlinkable identities
)
