/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

// SignerConfig contains the crypto material to set up an idemix signing identity
type SignerConfig struct {
	// Cred represents the serialized idemix credential of the default signer
	Cred []byte `protobuf:"bytes,1,opt,name=Cred,proto3" json:"Cred,omitempty"`
	// Sk is the secret key of the default signer, corresponding to credential Cred
	Sk []byte `protobuf:"bytes,2,opt,name=Sk,proto3" json:"Sk,omitempty"`
	// OrganizationalUnitIdentifier defines the organizational unit the default signer is in
	OrganizationalUnitIdentifier string `protobuf:"bytes,3,opt,name=organizational_unit_identifier,json=organizationalUnitIdentifier" json:"organizational_unit_identifier,omitempty"`
	// IsAdmin defines whether the default signer is admin or not
	IsAdmin bool `protobuf:"varint,4,opt,name=is_admin,json=isAdmin" json:"is_admin,omitempty"`
	// EnrollmentID contains the enrollment id of this signer
	EnrollmentID string `protobuf:"bytes,5,opt,name=enrollment_id,json=enrollmentId" json:"enrollment_id,omitempty"`
}

// GetCred returns credential associated with this signer config
func (s *SignerConfig) GetCred() []byte {
	return s.Cred

}

// GetSk returns secret key associated with this signer config
func (s *SignerConfig) GetSk() []byte {
	return s.Sk
}

// GetOrganizationalUnitIdentifier returns OU of the user associated with this signer config
func (s *SignerConfig) GetOrganizationalUnitIdentifier() string {
	return s.OrganizationalUnitIdentifier
}

// GetIsAdmin returns true if the user associated with this signer config is an admin, else
// returns false
func (s *SignerConfig) GetIsAdmin() bool {
	return s.IsAdmin
}

// GetEnrollmentID returns enrollment ID of the user associated with this signer config
func (s *SignerConfig) GetEnrollmentID() string {
	return s.EnrollmentID
}
