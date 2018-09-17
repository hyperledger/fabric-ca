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
	// Role defines whether the default signer is admin, member, peer, or client
	Role int `protobuf:"varint,4,opt,name=role,json=role" json:"role,omitempty"`
	// EnrollmentID contains the enrollment id of this signer
	EnrollmentID string `protobuf:"bytes,5,opt,name=enrollment_id,json=enrollmentId" json:"enrollment_id,omitempty"`
	// CRI contains a serialized Credential Revocation Information
	CredentialRevocationInformation []byte `protobuf:"bytes,6,opt,name=credential_revocation_information,json=credentialRevocationInformation,proto3" json:"credential_revocation_information,omitempty"`
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

// GetRole returns true if the user associated with this signer config is an admin, else
// returns role
func (s *SignerConfig) GetRole() int {
	return s.Role
}

// GetEnrollmentID returns enrollment ID of the user associated with this signer config
func (s *SignerConfig) GetEnrollmentID() string {
	return s.EnrollmentID
}

// GetCredentialRevocationInformation returns CRI
func (s *SignerConfig) GetCredentialRevocationInformation() []byte {
	return s.CredentialRevocationInformation
}
