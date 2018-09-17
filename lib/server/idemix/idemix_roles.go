/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

// Role : Represents a IdemixRole
type Role int32

// The expected roles are 4; We can combine them using a bitmask
const (
	MEMBER Role = 1
	ADMIN  Role = 2
	CLIENT Role = 4
	PEER   Role = 8
	// Next role values: 16, 32, 64 ...
)

func (role Role) getValue() int {
	return int(role)
}

// CheckRole Prove that the desired role is contained or not in the bitmask
func CheckRole(bitmask int, role Role) bool {
	return (bitmask & role.getValue()) == role.getValue()
}

// GetRoleMask Receive a list of roles to combine in a single bitmask
func GetRoleMask(roles []Role) int {
	mask := 0
	for _, role := range roles {
		mask = mask | role.getValue()
	}
	return mask
}
