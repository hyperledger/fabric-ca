/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"encoding/json"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	cadbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/hyperledger/fabric-ca/lib/server/user"
	cadbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/jmoiron/sqlx"
	"github.com/kisielk/sqlstruct"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ocsp"
)

// Match to sqlx
func init() {
	sqlstruct.TagName = "db"
}

const (
	insertUser = `
INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments, level, incorrect_password_attempts)
VALUES (:id, :token, :type, :affiliation, :attributes, :state, :max_enrollments, :level, :incorrect_password_attempts);`

	deleteUser = `
DELETE FROM users
	WHERE (id = ?);`

	updateUser = `
UPDATE users
SET token = :token, type = :type, affiliation = :affiliation, attributes = :attributes, state = :state, max_enrollments = :max_enrollments, level = :level, incorrect_password_attempts = :incorrect_password_attempts
	WHERE (id = :id);`

	getUser = `
SELECT * FROM users
	WHERE (id = ?)`

	insertAffiliation = `
INSERT INTO affiliations (name, prekey, level)
	VALUES (?, ?, ?)`

	deleteAffiliation = `
DELETE FROM affiliations
	WHERE (name = ?)`

	deleteAffAndSubAff = `
DELETE FROM affiliations
	WHERE (name = ? OR name LIKE ?)`

	getAffiliationQuery = `
SELECT * FROM affiliations
	WHERE (name = ?)`

	getAllAffiliationsQuery = `
SELECT * FROM affiliations
	WHERE (name = ? OR name LIKE ?)`

	getIDsWithAffiliation = `
SELECT * FROM users
	WHERE (affiliation = ?)`

	updateAffiliation = `
UPDATE affiliations
	SET name = ?, prekey = ?
	WHERE (name = ?)`
)

// Accessor implements db.Accessor interface.
type Accessor struct {
	db db.FabricCADB
}

// NewDBAccessor is a constructor for the database API
func NewDBAccessor(cadb db.FabricCADB) *Accessor {
	return &Accessor{
		db: cadb,
	}
}

func (d *Accessor) checkDB() error {
	if d.db == nil {
		return errors.New("Failed to correctly setup database connection")
	}
	return nil
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *Accessor) SetDB(db db.FabricCADB) {
	d.db = db
}

// InsertUser inserts user into database
func (d *Accessor) InsertUser(user *cadbuser.Info) error {
	if user == nil {
		return errors.New("User is not defined")
	}
	log.Debugf("DB: Add identity %s", user.Name)

	err := d.checkDB()
	if err != nil {
		return err
	}

	attrBytes, err := json.Marshal(user.Attributes)
	if err != nil {
		return err
	}

	// Hash the password before storing it
	pwd := []byte(user.Pass)
	pwd, err = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "Failed to hash password")
	}

	// Store the user record in the DB
	res, err := d.db.NamedExec("InsertUser", insertUser, &cadbuser.Record{
		Name:                      user.Name,
		Pass:                      pwd,
		Type:                      user.Type,
		Affiliation:               user.Affiliation,
		Attributes:                string(attrBytes),
		State:                     user.State,
		MaxEnrollments:            user.MaxEnrollments,
		Level:                     user.Level,
		IncorrectPasswordAttempts: 0,
	})

	if err != nil {
		return errors.Wrapf(err, "Error adding identity '%s' to the database", user.Name)
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if numRowsAffected == 0 {
		return errors.Errorf("Failed to add identity %s to the database", user.Name)
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected to add one record to the database, but %d records were added", numRowsAffected)
	}

	log.Debugf("Successfully added identity %s to the database", user.Name)

	return nil

}

// DeleteUser deletes user from database
func (d *Accessor) DeleteUser(id string) (user.User, error) {
	log.Debugf("DB: Delete identity %s", id)

	result, err := d.doTransaction(d.deleteUserTx, id, ocsp.CessationOfOperation) // 5 (cessationofoperation) reason for certificate revocation
	if err != nil {
		return nil, err
	}

	userRec := result.(*cadbuser.Record)
	user := cadbuser.New(userRec, d.db)

	return user, nil
}

func (d *Accessor) deleteUserTx(tx *sqlx.Tx, args ...interface{}) (interface{}, error) {
	id := args[0].(string)
	reason := args[1].(int)

	var userRec cadbuser.Record
	err := tx.Get(&userRec, tx.Rebind(getUser), id)
	if err != nil {
		return nil, cadbutil.GetError(err, "User")
	}

	_, err = tx.Exec(tx.Rebind(deleteUser), id)
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrDBDeleteUser, "Error deleting identity '%s': %s", id, err)
	}

	record := &db.CertRecord{
		ID: id,
	}
	record.Reason = reason

	_, err = tx.NamedExec(tx.Rebind(updateRevokeSQL), record)
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrDBDeleteUser, "Error encountered while revoking certificates for identity '%s' that is being deleted: %s", id, err)
	}

	return &userRec, nil
}

// UpdateUser updates user in database
func (d *Accessor) UpdateUser(user *cadbuser.Info, updatePass bool) error {
	if user == nil {
		return errors.New("User is not defined")
	}

	log.Debugf("DB: Update identity %s", user.Name)
	err := d.checkDB()
	if err != nil {
		return err
	}

	attributes, err := json.Marshal(user.Attributes)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal user attributes")
	}

	// Hash the password before storing it
	pwd := []byte(user.Pass)
	if updatePass {
		pwd, err = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
		if err != nil {
			return errors.Wrap(err, "Failed to hash password")
		}
	}

	// Store the updated user entry
	res, err := d.db.NamedExec("UpdateUser", updateUser, cadbuser.Record{
		Name:                      user.Name,
		Pass:                      pwd,
		Type:                      user.Type,
		Affiliation:               user.Affiliation,
		Attributes:                string(attributes),
		State:                     user.State,
		MaxEnrollments:            user.MaxEnrollments,
		Level:                     user.Level,
		IncorrectPasswordAttempts: user.IncorrectPasswordAttempts,
	})

	if err != nil {
		return errors.Wrap(err, "Failed to update identity record")
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return errors.New("No identity records were updated")
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected one identity record to be updated, but %d records were updated", numRowsAffected)
	}

	return err

}

// GetUser gets user from database
func (d *Accessor) GetUser(id string, attrs []string) (user.User, error) {
	log.Debugf("DB: Getting identity %s", id)

	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var userRec cadbuser.Record
	err = d.db.Get("GetUser", &userRec, d.db.Rebind(getUser), id)
	if err != nil {
		return nil, cadbutil.GetError(err, "User")
	}

	return cadbuser.New(&userRec, d.db), nil
}

// InsertAffiliation inserts affiliation into database
func (d *Accessor) InsertAffiliation(name string, prekey string, level int) error {
	log.Debugf("DB: Add affiliation %s", name)
	err := d.checkDB()
	if err != nil {
		return err
	}
	dbType := d.db.DriverName()
	// InnoDB store engine for MySQL does not allow more than 767 bytes
	// in a 'UNIQUE' column. To work around this, the UNIQUE constraint was removed
	// from the 'name' column in the affiliations table for MySQL to allow for up to 1024
	// characters to be stored. In doing this, a check is needed on MySQL to check
	// if the affiliation exists before adding it to prevent duplicate entries.
	if dbType == "mysql" {
		aff, _ := d.GetAffiliation(name)
		if aff != nil {
			log.Debugf("Affiliation '%s' already exists", name)
			return nil
		}
	}
	_, err = d.db.Exec("InsertAffiliation", d.db.Rebind(insertAffiliation), name, prekey, level)
	if err != nil {
		if (!strings.Contains(err.Error(), "UNIQUE constraint failed") && dbType == "sqlite3") || (!strings.Contains(err.Error(), "duplicate key value") && dbType == "postgres") {
			return err
		}
		log.Debugf("Affiliation '%s' already exists", name)
		return nil
	}
	log.Debugf("Affiliation '%s' added", name)

	return nil
}

// DeleteAffiliation deletes affiliation from database. Using the force option with identity removal allowed
// this will also delete the identities associated with removed affiliations, and also delete the certificates
// for the identities removed
func (d *Accessor) DeleteAffiliation(name string, force, identityRemoval, isRegistrar bool) (*user.DbTxResult, error) {
	log.Debugf("DB: Delete affiliation %s", name)

	_, err := d.GetAffiliation(name)
	if err != nil {
		return nil, err
	}

	result, err := d.doTransaction(d.deleteAffiliationTx, name, force, identityRemoval, isRegistrar)
	if err != nil {
		return nil, err
	}

	deletedInfo := result.(*user.DbTxResult)

	return deletedInfo, nil
}

func (d *Accessor) deleteAffiliationTx(tx *sqlx.Tx, args ...interface{}) (interface{}, error) {
	var err error

	name := args[0].(string)
	force := args[1].(bool)
	identityRemoval := args[2].(bool)
	isRegistar := args[3].(bool)

	subAffName := name + ".%"
	query := "SELECT * FROM users WHERE (affiliation = ? OR affiliation LIKE ?)"
	ids := []cadbuser.Record{}
	err = tx.Select(&ids, tx.Rebind(query), name, subAffName)
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrRemoveAffDB, "Failed to select users with sub-affiliation of '%s': %s", name, err)
	}

	idNames := []string{}
	for _, id := range ids {
		idNames = append(idNames, id.Name)
	}
	idNamesStr := strings.Join(idNames, ",")

	// First check that all settings are correct
	if len(ids) > 0 {
		if !isRegistar {
			return nil, caerrors.NewAuthorizationErr(caerrors.ErrUpdateConfigRemoveAff, "Removing affiliation affects identities, but caller is not a registrar")
		}
		if !identityRemoval {
			return nil, caerrors.NewAuthorizationErr(caerrors.ErrUpdateConfigRemoveAff, "Identity removal is not allowed on server")
		}
		if !force {
			// If force option is not specified, only delete affiliation if there are no identities that have that affiliation
			return nil, caerrors.NewAuthorizationErr(caerrors.ErrUpdateConfigRemoveAff, "Cannot delete affiliation '%s'. The affiliation has the following identities associated: %s. Need to use 'force' to remove identities and affiliation", name, idNamesStr)
		}
	}

	allAffs := []db.AffiliationRecord{}
	err = tx.Select(&allAffs, tx.Rebind(getAllAffiliationsQuery), name, subAffName)
	if err != nil {
		return nil, cadbutil.GetError(err, "Affiliation")
	}

	affNames := []string{}
	for _, aff := range allAffs {
		affNames = append(affNames, aff.Name)
	}
	affNamesStr := strings.Join(affNames, ",")

	if len(allAffs) > 1 {
		if !force {
			// If force option is not specified, only delete affiliation if there are no sub-affiliations
			return nil, caerrors.NewAuthorizationErr(caerrors.ErrUpdateConfigRemoveAff, "Cannot delete affiliation '%s'. The affiliation has the following sub-affiliations: %s. Need to use 'force' to remove affiliation and sub-affiliations", name, affNamesStr)
		}
	}

	// Now proceed with deletion

	// delete any associated identities and certificates
	if len(ids) > 0 {
		log.Debugf("IDs '%s' to be removed based on affiliation '%s' removal", idNamesStr, name)

		// Delete all the identities in one database request
		query := "DELETE FROM users WHERE (id IN (?))"
		inQuery, args, err := sqlx.In(query, idNames)
		if err != nil {
			return nil, caerrors.NewHTTPErr(500, caerrors.ErrRemoveAffDB, "Failed to construct query '%s': %s", query, err)
		}
		_, err = tx.Exec(tx.Rebind(inQuery), args...)
		if err != nil {
			return nil, caerrors.NewHTTPErr(500, caerrors.ErrRemoveAffDB, "Failed to execute query '%s' for multiple identity removal: %s", query, err)
		}

		// Revoke all the certificates associated with the removed identities above with reason of "affiliationchange" (3)
		query = "UPDATE certificates SET status='revoked', revoked_at=CURRENT_TIMESTAMP, reason = ? WHERE (id IN (?) AND status != 'revoked')"
		inQuery, args, err = sqlx.In(query, ocsp.AffiliationChanged, idNames)
		if err != nil {
			return nil, caerrors.NewHTTPErr(500, caerrors.ErrRemoveAffDB, "Failed to construct query '%s': %s", query, err)
		}
		_, err = tx.Exec(tx.Rebind(inQuery), args...)
		if err != nil {
			return nil, caerrors.NewHTTPErr(500, caerrors.ErrRemoveAffDB, "Failed to execute query '%s' for multiple certificate removal: %s", query, err)
		}
	}

	log.Debugf("All affiliations to be removed: %s", allAffs)

	// Delete the requested affiliation and it's subaffiliations
	_, err = tx.Exec(tx.Rebind(deleteAffAndSubAff), name, subAffName)
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrRemoveAffDB, "Failed to delete affiliation '%s': %s", name, err)
	}

	// Return the identities and affiliations that were removed
	result := d.getResult(ids, allAffs)

	return result, nil
}

// GetAffiliation gets affiliation from database
func (d *Accessor) GetAffiliation(name string) (spi.Affiliation, error) {
	log.Debugf("DB: Get affiliation %s", name)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var affiliationRecord db.AffiliationRecord

	err = d.db.Get("GetAffiliation", &affiliationRecord, d.db.Rebind(getAffiliationQuery), name)
	if err != nil {
		return nil, cadbutil.GetError(err, "Affiliation")
	}

	affiliation := spi.NewAffiliation(affiliationRecord.Name, affiliationRecord.Prekey, affiliationRecord.Level)

	return affiliation, nil
}

// GetAffiliationTree returns the requested affiliation and affiliations below
func (d *Accessor) GetAffiliationTree(name string) (*user.DbTxResult, error) {
	log.Debugf("DB: Get affiliation tree for '%s'", name)

	if name != "" {
		_, err := d.GetAffiliation(name)
		if err != nil {
			return nil, err
		}
	}

	result, err := d.doTransaction(d.getAffiliationTreeTx, name)
	if err != nil {
		return nil, err
	}

	getResult := result.(*user.DbTxResult)

	return getResult, nil
}

// GetAffiliation gets affiliation from database
func (d *Accessor) getAffiliationTreeTx(tx *sqlx.Tx, args ...interface{}) (interface{}, error) {
	name := args[0].(string)

	log.Debugf("DB: Get affiliation tree for %s", name)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	// Getting affiliations
	allAffs := []db.AffiliationRecord{}
	if name == "" { // Requesting all affiliations
		err = tx.Select(&allAffs, tx.Rebind("SELECT * FROM affiliations"))
		if err != nil {
			return nil, caerrors.NewHTTPErr(500, caerrors.ErrGettingAffiliation, "Failed to get affiliation tree for '%s': %s", name, err)
		}
	} else {
		err = tx.Select(&allAffs, tx.Rebind("Select * FROM affiliations where (name LIKE ?) OR (name = ?)"), name+".%", name)
		if err != nil {
			return nil, caerrors.NewHTTPErr(500, caerrors.ErrGettingAffiliation, "Failed to get affiliation tree for '%s': %s", name, err)
		}
	}

	ids := []cadbuser.Record{} // TODO: Return identities associated with these affiliations
	result := d.getResult(ids, allAffs)
	return result, nil
}

// GetUserLessThanLevel returns all identities that are less than the level specified
// Otherwise, returns no users if requested level is zero
func (d *Accessor) GetUserLessThanLevel(level int) ([]user.User, error) {
	if level == 0 {
		return []user.User{}, nil
	}

	rows, err := d.db.Queryx("GetUserLessThanLevel", d.db.Rebind("SELECT * FROM users WHERE (level < ?) OR (level IS NULL)"), level)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get identities that need to be updated")
	}

	allUsers := []user.User{}

	for rows.Next() {
		var user cadbuser.Record
		rows.StructScan(&user)
		cadbuser := cadbuser.New(&user, d.db)
		allUsers = append(allUsers, cadbuser)
	}

	return allUsers, nil
}

// GetAllAffiliations gets the requested affiliation and any sub affiliations from the database
func (d *Accessor) GetAllAffiliations(name string) (*sqlx.Rows, error) {
	log.Debugf("DB: Get affiliation %s", name)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	if name == "" { // Requesting all affiliations
		rows, err := d.db.Queryx("GetAllAffiliations", d.db.Rebind("SELECT * FROM affiliations"))
		if err != nil {
			return nil, err
		}
		return rows, nil
	}

	rows, err := d.db.Queryx("GetAllAffiliations", d.db.Rebind(getAllAffiliationsQuery), name, name+".%")
	if err != nil {
		return nil, err
	}

	return rows, nil
}

// GetFilteredUsers returns all identities that fall under the affiliation and types
func (d *Accessor) GetFilteredUsers(affiliation, types string) (*sqlx.Rows, error) {
	log.Debugf("DB: Get all identities per affiliation '%s' and types '%s'", affiliation, types)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	typesArray := strings.Split(types, ",")
	for i := range typesArray {
		typesArray[i] = strings.TrimSpace(typesArray[i])
	}

	// If root affiliation, allowed to get back users of all affiliations
	if affiliation == "" {
		if util.ListContains(types, "*") { // If type is '*', allowed to get back of all types
			query := "SELECT * FROM users"
			rows, err := d.db.Queryx("GetFilteredUsers", d.db.Rebind(query))
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to execute query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
			}
			return rows, nil
		}

		query := "SELECT * FROM users WHERE (type IN (?))"
		query, args, err := sqlx.In(query, typesArray)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to construct query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
		rows, err := d.db.Queryx("GetFilteredUsers", d.db.Rebind(query), args...)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to execute query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
		return rows, nil
	}

	subAffiliation := affiliation + ".%"
	if util.ListContains(types, "*") { // If type is '*', allowed to get back of all types for requested affiliation
		query := "SELECT * FROM users WHERE ((affiliation = ?) OR (affiliation LIKE ?))"
		rows, err := d.db.Queryx("GetFilteredUsers", d.db.Rebind(query))
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to execute query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
		}
		return rows, nil
	}

	query := "SELECT * FROM users WHERE ((affiliation = ?) OR (affiliation LIKE ?)) AND (type IN (?))"
	inQuery, args, err := sqlx.In(query, affiliation, subAffiliation, typesArray)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to construct query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
	}
	rows, err := d.db.Queryx("GetFilteredUsers", d.db.Rebind(inQuery), args...)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to execute query '%s' for affiliation '%s' and types '%s'", query, affiliation, types)
	}

	return rows, nil

}

// ModifyAffiliation renames the affiliation and updates all identities to use the new affiliation depending on
// the value of the "force" parameter
func (d *Accessor) ModifyAffiliation(oldAffiliation, newAffiliation string, force, isRegistrar bool) (*user.DbTxResult, error) {
	log.Debugf("DB: Modify affiliation from '%s' to '%s'", oldAffiliation, newAffiliation)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	// Check to see if the affiliation being modifies exists in the affiliation table
	_, err = d.GetAffiliation(oldAffiliation)
	if err != nil {
		return nil, err
	}

	// Check to see if the new affiliation being requested exists in the affiliation table
	_, err = d.GetAffiliation(newAffiliation)
	if err == nil {
		return nil, caerrors.NewHTTPErr(400, caerrors.ErrUpdateConfigModifyAff, "Affiliation '%s' already exists", newAffiliation)
	}

	result, err := d.doTransaction(d.modifyAffiliationTx, oldAffiliation, newAffiliation, force, isRegistrar)
	if err != nil {
		return nil, err
	}

	modifiedInfo := result.(*user.DbTxResult)

	return modifiedInfo, nil
}

func (d *Accessor) modifyAffiliationTx(tx *sqlx.Tx, args ...interface{}) (interface{}, error) {
	oldAffiliation := args[0].(string)
	newAffiliation := args[1].(string)
	force := args[2].(bool)
	isRegistar := args[3].(bool)

	// Get the affiliation records including all sub affiliations
	var allOldAffiliations []db.AffiliationRecord
	err := tx.Select(&allOldAffiliations, tx.Rebind(getAllAffiliationsQuery), oldAffiliation, oldAffiliation+".%")
	if err != nil {
		return nil, err
	}

	log.Debugf("Affiliations to be modified %+v", allOldAffiliations)

	// Iterate through all the affiliations found and update to use new affiliation path
	idsUpdated := []string{}
	for _, affiliation := range allOldAffiliations {
		var idsWithOldAff []cadbuser.Record
		oldPath := affiliation.Name
		oldParentPath := affiliation.Prekey
		newPath := strings.Replace(oldPath, oldAffiliation, newAffiliation, 1)
		newParentPath := strings.Replace(oldParentPath, oldAffiliation, newAffiliation, 1)
		log.Debugf("oldPath: %s, newPath: %s, oldParentPath: %s, newParentPath: %s", oldPath, newPath, oldParentPath, newParentPath)

		// Select all users that are using the old affiliation
		err = tx.Select(&idsWithOldAff, tx.Rebind(getIDsWithAffiliation), oldPath)
		if err != nil {
			return nil, err
		}
		if len(idsWithOldAff) > 0 {
			if !isRegistar {
				return nil, caerrors.NewAuthorizationErr(caerrors.ErrMissingRegAttr, "Modifying affiliation affects identities, but caller is not a registrar")
			}
			// Get the list of names of the identities that need to be updated to use new affiliation
			ids := []string{}
			for _, id := range idsWithOldAff {
				ids = append(ids, id.Name)
			}

			if force {
				log.Debugf("Identities %s to be updated to use new affiliation of '%s' from '%s'", ids, newPath, oldPath)

				query := "Update users SET affiliation = ? WHERE (id IN (?))"
				inQuery, args, err := sqlx.In(query, newPath, ids)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to construct query '%s'", query)
				}
				_, err = tx.Exec(tx.Rebind(inQuery), args...)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to execute query '%s' for multiple certificate removal", query)
				}

				// If user's affiliation is being updated, need to also update 'hf.Affiliation' attribute of user
				for _, userRec := range idsWithOldAff {
					user := cadbuser.New(&userRec, d.db)
					currentAttrs, _ := user.GetAttributes(nil)                            // Get all current user attributes
					userAff := cadbuser.GetAffiliation(user)                              // Get the current affiliation
					newAff := strings.Replace(userAff, oldAffiliation, newAffiliation, 1) // Replace old affiliation with new affiliation
					userAttrs := cadbuser.GetNewAttributes(currentAttrs, []api.Attribute{ // Generate the new set of attributes for user
						api.Attribute{
							Name:  attr.Affiliation,
							Value: newAff,
						},
					})

					attrBytes, err := json.Marshal(userAttrs)
					if err != nil {
						return nil, err
					}

					// Update attributes
					query := "UPDATE users SET attributes = ? where (id = ?)"
					id := user.GetName()
					res, err := tx.Exec(tx.Rebind(query), string(attrBytes), id)
					if err != nil {
						return nil, err
					}

					numRowsAffected, err := res.RowsAffected()
					if err != nil {
						return nil, errors.Wrap(err, "Failed to get number of rows affected")
					}

					if numRowsAffected == 0 {
						return nil, errors.Errorf("No rows were affected when updating the state of identity %s", id)
					}

					if numRowsAffected != 1 {
						return nil, errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, id)
					}
				}
			} else {
				// If force option is not specified, can only modify affiliation if there are no identities that have that affiliation
				idNamesStr := strings.Join(ids, ",")
				return nil, caerrors.NewHTTPErr(400, caerrors.ErrUpdateConfigModifyAff, "The request to modify affiliation '%s' has the following identities associated: %s. Need to use 'force' to remove identities and affiliation", oldAffiliation, idNamesStr)
			}

			idsUpdated = append(idsUpdated, ids...)
		}

		// Update the affiliation record in the database to use new affiliation path
		res := tx.MustExec(tx.Rebind(updateAffiliation), newPath, newParentPath, oldPath)
		numRowsAffected, err := res.RowsAffected()
		if err != nil {
			return nil, errors.Errorf("Failed to get number of rows affected")
		}
		if numRowsAffected == 0 {
			return nil, errors.Errorf("Failed to update any affiliation records for '%s'", oldPath)
		}
	}

	// Generate the result set that has all identities with their new affiliation and all renamed affiliations
	var idsWithNewAff []cadbuser.Record
	if len(idsUpdated) > 0 {
		query := "Select * FROM users WHERE (id IN (?))"
		inQuery, args, err := sqlx.In(query, idsUpdated)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to construct query '%s'", query)
		}
		err = tx.Select(&idsWithNewAff, tx.Rebind(inQuery), args...)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to execute query '%s' for getting users with new affiliation", query)
		}
	}

	allNewAffs := []db.AffiliationRecord{}
	err = tx.Select(&allNewAffs, tx.Rebind("Select * FROM affiliations where (name LIKE ?) OR (name = ?)"), newAffiliation+".%", newAffiliation)
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrGettingAffiliation, "Failed to get affiliation tree for '%s': %s", newAffiliation, err)
	}

	// Return the identities and affiliations that were modified
	result := d.getResult(idsWithNewAff, allNewAffs)

	return result, nil
}

func (d *Accessor) doTransaction(doit func(tx *sqlx.Tx, args ...interface{}) (interface{}, error), args ...interface{}) (interface{}, error) {
	err := d.checkDB()
	if err != nil {
		return nil, err
	}
	tx := d.db.MustBegin()
	result, err := doit(tx, args...)
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			log.Errorf("Error encounted while rolling back transaction: %s", err2)
			return nil, err
		}
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.Wrap(err, "Error encountered while committing transaction")
	}

	return result, nil
}

// Returns the identities and affiliations that were modified
func (d *Accessor) getResult(ids []cadbuser.Record, affs []db.AffiliationRecord) *user.DbTxResult {
	// Collect all the identities that were modified
	identities := []user.User{}
	for _, id := range ids {
		identities = append(identities, cadbuser.New(&id, d.db))
	}

	// Collect the name of all affiliations that were modified
	affiliations := []spi.Affiliation{}
	for _, aff := range affs {
		newAff := spi.NewAffiliation(aff.Name, aff.Prekey, aff.Level)
		affiliations = append(affiliations, newAff)
	}

	return &user.DbTxResult{
		Affiliations: affiliations,
		Identities:   identities,
	}
}
