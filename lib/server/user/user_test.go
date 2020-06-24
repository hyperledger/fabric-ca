/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package user_test

import (
	"errors"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/lib/server/user/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/bcrypt"
)

var _ = Describe("user", func() {
	var (
		userRecord *user.Record
		mockUserDB *mocks.UserDB
		mockResult *mocks.Result
		u          *user.Impl
	)

	BeforeEach(func() {
		mockUserDB = &mocks.UserDB{}
		mockResult = &mocks.Result{}

		pass, err := bcrypt.GenerateFromPassword([]byte("password"), 1)
		Expect(err).NotTo(HaveOccurred())

		attributes := `[{"name": "hf.Registrar.Roles", "value": "peer", "ecert": false},{"name": "attr0", "value": "attr0Value", "ecert": false}]`
		userRecord = &user.Record{
			Name:           "testuser",
			Type:           "client",
			Pass:           pass,
			MaxEnrollments: 100,
			Attributes:     attributes,
		}

		u = user.New(userRecord, mockUserDB)
	})

	It("creates a new user", func() {
		Expect(u).NotTo(BeNil())
		Expect(u.GetName()).To(Equal("testuser"))
		Expect(u.GetType()).To(Equal("client"))
		Expect(u.GetMaxEnrollments()).To(Equal(100))
	})

	Context("Setlevel", func() {
		It("returns an error if db fails to execute query", func() {
			mockUserDB.ExecReturns(nil, errors.New("failed to execute"))

			err := u.SetLevel(2)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to execute"))
		})

		It("returns an error if failed to get number of rows affected", func() {
			mockResult.RowsAffectedReturns(int64(1), errors.New("error"))
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.SetLevel(2)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to get number of rows affected: error"))
		})

		It("returns an error if number of rows affected equals 0", func() {
			mockResult.RowsAffectedReturns(int64(0), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.SetLevel(2)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("No rows were affected when updating the state of identity testuser"))
		})

		It("returns an error if number of rows affected is not 1", func() {
			mockResult.RowsAffectedReturns(int64(3), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.SetLevel(2)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("3 rows were affected when updating the state of identity testuser"))
		})

		It("sets the user's level", func() {
			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.SetLevel(2)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Login", func() {
		It("returns an error if incorrect password used", func() {
			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.Login("badpass", -1)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Password mismatch"))
		})

		It("returns an error if trying to enroll with max enrollment value of 0", func() {
			u.MaxEnrollments = 0
			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.Login("password", -1)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Zero is an invalid value for maximum enrollments on identity 'testuser'"))
		})

		It("returns an error if user is revoked", func() {
			u.MaxEnrollments = 1
			u.State = -1

			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.Login("password", -1)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("User testuser is revoked; access denied"))
		})

		It("sets the max enrollment value of the user greater than the ca's max enrollment value to be ca's max value", func() {
			u.MaxEnrollments = 4
			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)

			u.Login("password", 2)
			Expect(u.MaxEnrollments).To(Equal(2))
		})

		It("returns an if user's state value exceeds or is equal to user's max enrollment value", func() {
			u.MaxEnrollments = 4
			u.State = 4
			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.Login("password", -1)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("The identity testuser has already enrolled 4 times, it has reached its maximum enrollment allowance"))
		})

		It("logins in user", func() {
			u.MaxEnrollments = 4
			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.Login("password", -1)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("IncrementIncorrectPasswordAttempts", func() {
		It("returns an error if db fails to execute query", func() {
			mockUserDB.ExecReturns(nil, errors.New("failed to execute"))

			err := u.IncrementIncorrectPasswordAttempts()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to execute"))
		})

		It("returns an error if failed to get number of rows affected", func() {
			mockResult.RowsAffectedReturns(int64(1), errors.New("error"))
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.IncrementIncorrectPasswordAttempts()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to get number of rows affected: error"))
		})

		It("returns an error if number of rows affected equals 0", func() {
			mockResult.RowsAffectedReturns(int64(0), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.IncrementIncorrectPasswordAttempts()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("No rows were affected when updating the state of identity testuser"))
		})

		It("returns an error if number of rows affected is not 1", func() {
			mockResult.RowsAffectedReturns(int64(3), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.IncrementIncorrectPasswordAttempts()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("3 rows were affected when updating the state of identity testuser"))
		})

	})

	Context("LoginComplete", func() {
		It("returns an error if db fails to execute query", func() {
			mockUserDB.ExecReturns(nil, errors.New("failed to execute"))

			err := u.LoginComplete()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to update state of identity testuser to 1: failed to execute"))
		})

		It("returns an error if failed to get number of rows affected", func() {
			mockResult.RowsAffectedReturns(int64(1), errors.New("error"))
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.LoginComplete()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to get number of rows affected: error"))
		})

		It("returns an error if number of rows affected equals 0", func() {
			mockResult.RowsAffectedReturns(int64(0), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.LoginComplete()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("No rows were affected when updating the state of identity testuser"))
		})

		It("returns an error if number of rows affected is not 1", func() {
			mockResult.RowsAffectedReturns(int64(3), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.LoginComplete()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("3 rows were affected when updating the state of identity testuser"))
		})

		It("updates the state of the user by 1", func() {
			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)

			state := u.State
			err := u.LoginComplete()
			Expect(err).NotTo(HaveOccurred())
			Expect(u.State).To(Equal(state + 1))
		})
	})

	It("splits affiliation on dots and returns a string slice", func() {
		u.Affiliation = "foo.bar.xyz"
		aff := u.GetAffiliationPath()
		Expect(aff).To(Equal([]string{"foo", "bar", "xyz"}))
	})

	Context("revoke", func() {
		It("returns an error if fails to execute revoke query", func() {
			mockUserDB.ExecReturns(nil, errors.New("failed to execute"))

			err := u.Revoke()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to update state of identity testuser to -1: failed to execute"))
		})

		It("returns an error if failed to get number of rows affected", func() {
			mockResult.RowsAffectedReturns(int64(1), errors.New("error"))
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.Revoke()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to get number of rows affected: error"))
		})

		It("returns an error if number of rows affected equals 0", func() {
			mockResult.RowsAffectedReturns(int64(0), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.Revoke()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("No rows were affected when updating the state of identity testuser"))
		})

		It("returns an error if number of rows affected is not 1", func() {
			mockResult.RowsAffectedReturns(int64(3), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.Revoke()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("3 rows were affected when updating the state of identity testuser"))
		})

		It("updates the state of the user to -1", func() {
			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.Revoke()
			Expect(err).NotTo(HaveOccurred())
			Expect(u.State).To(Equal(-1))
		})
	})

	Context("is revoked", func() {
		It("returns true if user is revoked", func() {
			u.State = -1
			Expect(u.IsRevoked()).To(Equal(true))
		})

		It("returns false if user is not revoked", func() {
			Expect(u.IsRevoked()).To(Equal(false))
		})
	})

	Context("get attributes", func() {
		It("returns all attributes if passed nil", func() {
			attrs, err := u.GetAttributes(nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(attrs)).To(Equal(2))
		})

		It("returns only attributes that are requested", func() {
			attrs, err := u.GetAttributes([]string{"attr0"})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(attrs)).To(Equal(1))
			Expect(attrs[0].Name).To(Equal("attr0"))
		})

		It("returns an error if requested attribute does not exist", func() {
			_, err := u.GetAttributes([]string{"fakeAttr"})
			Expect(err).To(HaveOccurred())
		})
	})

	Context("get new attributes", func() {
		var modifyAttributes []api.Attribute

		BeforeEach(func() {
			modifyAttributes = []api.Attribute{
				api.Attribute{
					Name:  "attr1",
					Value: "attr1_value",
				},
			}
		})

		It("modifies existing attributes", func() {
			newAttributes := []api.Attribute{
				api.Attribute{
					Name:  "attr1",
					Value: "attr1_newvalue",
				},
			}

			attrs := user.GetNewAttributes(modifyAttributes, newAttributes)
			Expect(attrs).To(Equal([]api.Attribute{api.Attribute{Name: "attr1", Value: "attr1_newvalue", ECert: false}}))
		})

		It("add attributes if not found", func() {
			newAttributes := []api.Attribute{
				api.Attribute{
					Name:  "attr2",
					Value: "attr2_value",
				},
			}

			attrs := user.GetNewAttributes(modifyAttributes, newAttributes)
			Expect(attrs).To(Equal([]api.Attribute{api.Attribute{Name: "attr1", Value: "attr1_value", ECert: false}, api.Attribute{Name: "attr2", Value: "attr2_value", ECert: false}}))
		})

		It("deletes attribute if value specified for attribute is empty string", func() {
			newAttributes := []api.Attribute{
				api.Attribute{
					Name:  "attr1",
					Value: "",
				},
			}

			attrs := user.GetNewAttributes(modifyAttributes, newAttributes)
			Expect(attrs).To(Equal([]api.Attribute{}))
		})
	})

	Context("modify attributes", func() {
		var newAttributes []api.Attribute

		It("returns an error if fails to execute modify query", func() {
			mockUserDB.ExecReturns(nil, errors.New("failed to execute"))

			err := u.ModifyAttributesTx(mockUserDB, newAttributes)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to execute"))
		})

		It("returns an error if failed to get number of rows affected", func() {
			mockResult.RowsAffectedReturns(int64(1), errors.New("error"))
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.ModifyAttributes(newAttributes)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to get number of rows affected: error"))
		})

		It("returns an error if number of rows affected equals 0", func() {
			mockResult.RowsAffectedReturns(int64(0), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.ModifyAttributes(newAttributes)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("No rows were affected when updating the state of identity testuser"))
		})

		It("returns an error if number of rows affected is not 1", func() {
			mockResult.RowsAffectedReturns(int64(3), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err := u.ModifyAttributes(newAttributes)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("3 rows were affected when updating the state of identity testuser"))
		})

		It("modifies existing attributes", func() {
			newAttributes = []api.Attribute{
				api.Attribute{
					Name:  "attr1",
					Value: "attr1_newvalue",
				},
			}

			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.ModifyAttributes(newAttributes)
			Expect(err).NotTo(HaveOccurred())
		})

		It("modifies existing attributes using transaction", func() {
			newAttributes = []api.Attribute{
				api.Attribute{
					Name:  "attr1",
					Value: "attr1_newvalue",
				},
			}

			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)

			err := u.ModifyAttributesTx(mockUserDB, newAttributes)
			Expect(err).NotTo(HaveOccurred())
		})

	})

	Context("migrate", func() {
		It("adds new attributes to user", func() {
			_, err := u.GetAttribute("hf.Registrar.Attributes")
			Expect(err).To(HaveOccurred())
			_, err = u.GetAttribute("hf.AffiliationMgr")
			Expect(err).To(HaveOccurred())
			_, err = u.GetAttribute("hf.GenCRL")
			Expect(err).To(HaveOccurred())

			mockResult.RowsAffectedReturns(int64(1), nil)
			mockUserDB.ExecReturns(mockResult, nil)
			err = u.Migrate(mockUserDB)
			Expect(err).NotTo(HaveOccurred())
			val, err := u.GetAttribute("hf.Registrar.Attributes")
			Expect(err).NotTo(HaveOccurred())
			Expect(val.Value).To(Equal("*"))
			val, err = u.GetAttribute("hf.AffiliationMgr")
			Expect(err).NotTo(HaveOccurred())
			Expect(val.Value).To(Equal("true"))
			val, err = u.GetAttribute("hf.GenCRL")
			Expect(err).NotTo(HaveOccurred())
			Expect(val.Value).To(Equal("true"))
		})
	})

	Context("get user less than level", func() {
		It("returns users below level", func() {
			_, err := user.GetUserLessThanLevel(mockUserDB, 1)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
