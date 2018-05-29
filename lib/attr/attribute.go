/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package attr

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// AttributeControl interface gets the attributes associated with an identity
type AttributeControl interface {
	// GetAttribute returns the value for an attribute name
	GetAttribute(name string) (*api.Attribute, error)
}

type attributeType int

const (
	// BOOLEAN indicates that the attribute is of type boolean
	BOOLEAN attributeType = 1 + iota
	// LIST indicates that the attribute is of type list
	LIST
	// FIXED indicates that the attribute value is fixed and can't be modified
	FIXED
	// CUSTOM indicates that the attribute is a custom attribute
	CUSTOM
)

// Attribute names
const (
	Roles          = "hf.Registrar.Roles"
	DelegateRoles  = "hf.Registrar.DelegateRoles"
	Revoker        = "hf.Revoker"
	IntermediateCA = "hf.IntermediateCA"
	GenCRL         = "hf.GenCRL"
	RegistrarAttr  = "hf.Registrar.Attributes"
	AffiliationMgr = "hf.AffiliationMgr"
	EnrollmentID   = "hf.EnrollmentID"
	Type           = "hf.Type"
	Affiliation    = "hf.Affiliation"
)

// CanRegisterRequestedAttributes validates that the registrar can register the requested attributes
func CanRegisterRequestedAttributes(reqAttrs []api.Attribute, user, registrar AttributeControl) error {
	if len(reqAttrs) == 0 {
		return nil
	}

	log.Debugf("Checking to see if registrar can register the requested attributes: %+v", reqAttrs)

	for _, reqAttr := range reqAttrs {
		// Check if registrar is allowed to register requested attributes
		err := CanRegisterAttribute(&reqAttr, reqAttrs, user, registrar)
		if err != nil {
			return err
		}
	}

	return nil
}

// CanRegisterAttribute will iterate through the values of registrar's 'hf.Registrar.Attributes' attribute to check if registrar can register the requested attributes
func CanRegisterAttribute(requestedAttr *api.Attribute, allRequestedAttrs []api.Attribute, user, registrar AttributeControl) error {
	// Get registrar's 'hf.Registrar.Attributes' attribute to see which attributes registrar is allowed to register
	registrarAttrs, err := registrar.GetAttribute(RegistrarAttr)
	if err != nil {
		return errors.Errorf("Failed to get attribute '%s': %s", RegistrarAttr, err)
	}
	if registrarAttrs.Value == "" {
		return errors.Errorf("Registrar does not have any values for '%s' thus can't register any attributes", RegistrarAttr)
	}
	log.Debugf("Validating that registrar with the following values for hf.Registrar.Attributes '%+v' is authorized to register the requested attribute '%+v'", registrarAttrs.GetValue(), requestedAttr)
	callerHfRegisterAttrSlice := util.GetSliceFromList(registrarAttrs.Value, ",") // Remove any whitespace between the values and split on comma

	requestedAttrName := requestedAttr.GetName()

	err = canRegisterAttr(requestedAttrName, callerHfRegisterAttrSlice)
	if err != nil {
		return err
	}

	attrControl, err := getAttributeControl(requestedAttrName)
	if err != nil {
		return err
	}

	err = attrControl.isRegistrarAuthorized(requestedAttr, allRequestedAttrs, user, registrar)
	if err != nil {
		return errors.Errorf("Registrar is not authorized to register attribute: %s", err)
	}

	return nil
}

// attributeMap contains the control definition for reserverd (hf.) attributes
var attributeMap = initAttrs()

func initAttrs() map[string]*attributeControl {
	var attributeMap = make(map[string]*attributeControl)

	booleanAttributes := []string{Revoker, IntermediateCA, GenCRL, AffiliationMgr}

	for _, attr := range booleanAttributes {
		attributeMap[attr] = &attributeControl{
			name:              attr,
			requiresOwnership: true,
			attrType:          BOOLEAN,
		}
	}

	listAttributes := []string{Roles, DelegateRoles, RegistrarAttr}

	for _, attr := range listAttributes {
		attributeMap[attr] = &attributeControl{
			name:              attr,
			requiresOwnership: true,
			attrType:          LIST,
		}
	}

	fixedValueAttributes := []string{EnrollmentID, Type, Affiliation}

	for _, attr := range fixedValueAttributes {
		attributeMap[attr] = &attributeControl{
			name:              attr,
			requiresOwnership: false,
			attrType:          FIXED,
		}
	}

	return attributeMap
}

type attributeControl struct {
	name              string
	requiresOwnership bool
	attrType          attributeType
}

func (ac *attributeControl) getName() string {
	return ac.name
}

func (ac *attributeControl) isOwnershipRequired() bool {
	return ac.requiresOwnership
}

func (ac *attributeControl) isRegistrarAuthorized(requestedAttr *api.Attribute, allRequestedAttrs []api.Attribute, user, registrar AttributeControl) error {
	log.Debug("Performing authorization check...")
	requestedAttrName := requestedAttr.GetName()

	var callersAttrValue string
	if ac.isOwnershipRequired() {
		callersAttribute, err := registrar.GetAttribute(requestedAttrName)
		if err != nil {
			return errors.Errorf("Attribute '%s' requires ownership but the caller does not own this attribute: %s", requestedAttrName, err)
		}
		callersAttrValue = callersAttribute.GetValue()

		log.Debugf("Checking if caller is authorized to register attribute '%s' with the requested value of '%s'", requestedAttrName, requestedAttr.GetValue())
	}

	switch ac.attrType {
	case BOOLEAN:
		return ac.validateBooleanAttribute(requestedAttr, callersAttrValue)
	case LIST:
		return ac.validateListAttribute(requestedAttr, callersAttrValue, allRequestedAttrs, user)
	case FIXED:
		log.Debug("Requested attribute type is fixed")
		return errors.Errorf("Cannot register fixed value attribute '%s'", ac.getName())
	case CUSTOM:
		return nil
	}

	return nil
}

func (ac *attributeControl) validateBooleanAttribute(requestedAttr *api.Attribute, callersAttrValue string) error {
	log.Debug("Requested attribute type is boolean")
	requestedAttrValue := requestedAttr.GetValue()

	callerAttrValueBool, err := strconv.ParseBool(callersAttrValue)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Failed to get boolean value of '%s'", callersAttrValue))
	}
	if callerAttrValueBool {
		// Deleting an attribute if empty string is requested as value for attribute, no further validation necessary
		if requestedAttrValue == "" {
			return nil
		}
		_, err := strconv.ParseBool(requestedAttrValue)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to get boolean value of '%s'", requestedAttrValue))
		}
		return nil
	}
	return errors.Errorf("Caller has a value of 'false' for boolean attribute '%s', can't perform any actions on this attribute", ac.getName())
}

func (ac *attributeControl) validateListAttribute(requestedAttr *api.Attribute, callersAttrValue string, allRequestedAttrs []api.Attribute, user AttributeControl) error {
	log.Debug("Requested attribute type is list")
	requestedAttrValue := requestedAttr.GetValue()

	// Deleting an attribute if empty string is requested as value for attribute, no further validation necessary
	if requestedAttrValue == "" {
		return nil
	}

	callerRegisterAttrSlice := util.GetSliceFromList(callersAttrValue, ",") // Remove any whitespace between the values and split on comma

	// hf.Registrar.Attribute is a special type of list attribute. Need to check all the
	// requested attribute names as values to this attribute to make sure caller is allowed to register
	if ac.getName() == RegistrarAttr {
		err := checkHfRegistrarAttrValues(requestedAttr, allRequestedAttrs, user, callerRegisterAttrSlice)
		if err != nil {
			return err
		}
		return nil
	}
	// Make sure the values requested for attribute is equal to or a subset of the registrar's attribute
	err := ac.IsSubsetOf(requestedAttrValue, callersAttrValue)
	if err != nil {
		return err
	}
	// If requested attribute is 'hf.Registrar.DeletegateRoles', make sure it is equal or a subset of the user's hf.Registrar.Roles attribute
	if ac.getName() == DelegateRoles {
		err := checkDelegateRoleValues(allRequestedAttrs, user)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ac *attributeControl) IsSubsetOf(requestedAttrValue, callersAttrValue string) error {
	if (ac.getName() == Roles || ac.getName() == DelegateRoles) && util.ListContains(callersAttrValue, "*") {
		return nil
	}
	err := util.IsSubsetOf(requestedAttrValue, callersAttrValue)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("The requested values for attribute '%s' is a superset of the caller's attribute value", ac.getName()))
	}
	return nil
}

// Check if registrar has the proper authority to register the values for 'hf.Registrar.Attributes'.
// Registering 'hf.Registrar.Attributes' with a value that has a 'hf.' prefix requires that the user
// being registered to possess that hf. attribute. For example, if attribute is 'hf.Registrar.Attributes=hf.Revoker'
// then user being registered must possess 'hf.Revoker' for this to be a valid request.
func checkHfRegistrarAttrValues(reqAttr *api.Attribute, reqAttrs []api.Attribute, user AttributeControl, callerRegisterAttrSlice []string) error {
	log.Debug("Perform ownshership check for requested 'hf.' attributes for the values of 'hf.Registrar.Attributes'")

	valuesRequestedForHfRegistrarAttr := util.GetSliceFromList(reqAttr.Value, ",") // Remove any whitespace between the values and split on comma
	for _, requestedAttrValue := range valuesRequestedForHfRegistrarAttr {
		err := canRegisterAttr(requestedAttrValue, callerRegisterAttrSlice)
		if err != nil {
			return err
		}
		if strings.HasPrefix(requestedAttrValue, "hf.") {
			log.Debugf("Checking if value '%s' for hf.Registrar.Attribute is owned by user", requestedAttrValue)
			if !Exists(reqAttrs, requestedAttrValue) {
				// Attribute not present in the list of attributes being requested along side 'hf.Registrar.Attributes'
				// if user equals nil, this is a new user registration request
				if user == nil {
					return errors.Errorf("Requesting value of '%s' for 'hf.Registrar.Attributes', but the identity being registered is not being registered with this attribute", requestedAttrValue)
				}
				// If user not equal nil (modify user request), check to see if it possesses the attribute
				_, err := user.GetAttribute(requestedAttrValue)
				if err != nil {
					return errors.Errorf("Requesting value of '%s' for 'hf.Registrar.Attributes', but the identity does not possess this attribute nor is it being registered with this attribute", requestedAttrValue)
				}
			}
		}
	}
	return nil
}

func canRegisterAttr(requestedAttrName string, callerRegisterAttrSlice []string) error {
	log.Debugf("Checking if registrar can register attribute: %s", requestedAttrName)

	for _, regAttr := range callerRegisterAttrSlice {
		if strings.HasSuffix(regAttr, "*") { // Wildcard matching
			if strings.HasPrefix(requestedAttrName, strings.TrimRight(regAttr, "*")) {
				return nil
			}
		} else {
			if requestedAttrName == regAttr { // Exact name matching
				return nil
			}
		}
	}

	return errors.Errorf("Attribute is not part of caller's '%s' attribute list", callerRegisterAttrSlice)
}

// Make sure delegateRoles is not larger than roles
func checkDelegateRoleValues(reqAttrs []api.Attribute, user AttributeControl) error {
	roles := GetAttrValue(reqAttrs, Roles)
	if roles == "" { // If roles is not being updated in this request, query to get the current value of roles of user
		if user != nil { // If the is a user modify request, check to see if attribute already exists for user
			currentRoles, err := user.GetAttribute(Roles)
			if err == nil {
				roles = currentRoles.GetValue()
			}
		}
	}
	if util.ListContains(roles, "*") {
		return nil
	}
	delegateRoles := GetAttrValue(reqAttrs, DelegateRoles)
	err := util.IsSubsetOf(delegateRoles, roles)
	if err != nil {
		return errors.New("The delegateRoles field is a superset of roles")
	}
	return nil
}

func getAttributeControl(attrName string) (*attributeControl, error) {
	attrControl, found := attributeMap[attrName]
	if found {
		return attrControl, nil
	}

	if strings.HasPrefix(attrName, "hf.") {
		return nil, errors.Errorf("Registering attribute '%s' using a reserved prefix 'hf.', however this not a supported reserved attribute", attrName)
	}

	return &attributeControl{
		name:              attrName,
		requiresOwnership: false,
		attrType:          CUSTOM,
	}, nil
}

// Exists searches 'attrs' for the attribute with name 'name' and returns
// true if found
func Exists(attrs []api.Attribute, name string) bool {
	for _, attr := range attrs {
		if attr.Name == name {
			return true
		}
	}
	return false
}

// GetAttrValue searches 'attrs' for the attribute with name 'name' and returns
// its value, or "" if not found.
func GetAttrValue(attrs []api.Attribute, name string) string {
	for _, attr := range attrs {
		if attr.Name == name {
			return attr.Value
		}
	}
	return ""
}

// ConvertAttrs converts attribute string into an Attribute object array
func ConvertAttrs(inAttrs map[string]string) ([]api.Attribute, error) {
	var outAttrs []api.Attribute
	for name, value := range inAttrs {
		sattr := strings.Split(value, ":")
		if len(sattr) > 2 {
			return []api.Attribute{}, errors.Errorf("Multiple ':' characters not allowed "+
				"in attribute specification '%s'; The attributes have been discarded!", value)
		}
		attrFlag := ""
		if len(sattr) > 1 {
			attrFlag = sattr[1]
		}
		ecert := false
		switch strings.ToLower(attrFlag) {
		case "":
		case "ecert":
			ecert = true
		default:
			return []api.Attribute{}, errors.Errorf("Invalid attribute flag: '%s'", attrFlag)
		}
		outAttrs = append(outAttrs, api.Attribute{
			Name:  name,
			Value: sattr[0],
			ECert: ecert,
		})
	}
	return outAttrs, nil
}
