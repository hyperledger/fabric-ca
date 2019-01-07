/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldap

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	causer "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/lib/spi"
	ctls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	ldap "gopkg.in/ldap.v2"
)

var (
	errNotSupported = errors.New("Not supported")
	ldapURLRegex    = regexp.MustCompile("ldaps*://(\\S+):(\\S+)@")
)

// Config is the configuration object for this LDAP client
type Config struct {
	Enabled     bool   `def:"false" help:"Enable the LDAP client for authentication and attributes"`
	URL         string `help:"LDAP client URL of form ldap://adminDN:adminPassword@host[:port]/base" mask:"url"`
	UserFilter  string `def:"(uid=%s)" help:"The LDAP user filter to use when searching for users"`
	GroupFilter string `def:"(memberUid=%s)" help:"The LDAP group filter for a single affiliation group"`
	Attribute   AttrConfig
	TLS         ctls.ClientTLSConfig
}

// AttrConfig is attribute configuration information
type AttrConfig struct {
	Names      []string             `help:"The names of LDAP attributes to request on an LDAP search"`
	Converters []NameVal            // Used to convert an LDAP entry into a fabric-ca-server attribute
	Maps       map[string][]NameVal // Use to map an LDAP response to fabric-ca-server names
}

// NameVal is a name and value pair
type NameVal struct {
	Name  string
	Value string
}

// Implements Stringer interface for ldap.Config
// Calls util.StructToString to convert the Config struct to
// string.
func (c Config) String() string {
	return util.StructToString(&c)
}

// NewClient creates an LDAP client
func NewClient(cfg *Config, csp bccsp.BCCSP) (*Client, error) {
	log.Debugf("Creating new LDAP client for %+v", cfg)
	if cfg == nil {
		return nil, errors.New("LDAP configuration is nil")
	}
	if cfg.URL == "" {
		return nil, errors.New("LDAP configuration requires a 'URL'")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	var defaultPort string
	switch u.Scheme {
	case "ldap":
		defaultPort = "389"
	case "ldaps":
		defaultPort = "636"
	default:
		return nil, errors.Errorf("Invalid LDAP scheme: %s", u.Scheme)
	}
	var host, port string
	if strings.Index(u.Host, ":") < 0 {
		host = u.Host
		port = defaultPort
	} else {
		host, port, err = net.SplitHostPort(u.Host)
		if err != nil {
			return nil, errors.Wrapf(err, "Invalid LDAP host:port (%s)", u.Host)
		}
	}
	portVal, err := strconv.Atoi(port)
	if err != nil {
		return nil, errors.Wrapf(err, "Invalid LDAP port (%s)", port)
	}
	c := new(Client)
	c.Host = host
	c.Port = portVal
	c.UseSSL = u.Scheme == "ldaps"
	if u.User != nil {
		c.AdminDN = u.User.Username()
		c.AdminPassword, _ = u.User.Password()
	}
	c.Base = u.Path
	if c.Base != "" && strings.HasPrefix(c.Base, "/") {
		c.Base = c.Base[1:]
	}
	c.UserFilter = cfgVal(cfg.UserFilter, "(uid=%s)")
	c.GroupFilter = cfgVal(cfg.GroupFilter, "(memberUid=%s)")
	c.attrNames = cfg.Attribute.Names
	c.attrExprs = map[string]*userExpr{}
	for _, ele := range cfg.Attribute.Converters {
		ue, err := newUserExpr(c, ele.Name, ele.Value)
		if err != nil {
			return nil, err
		}
		c.attrExprs[ele.Name] = ue
		log.Debugf("Added LDAP mapping expression for attribute '%s'", ele.Name)
	}
	c.attrMaps = map[string]map[string]string{}
	for mapName, value := range cfg.Attribute.Maps {
		c.attrMaps[mapName] = map[string]string{}
		for _, ele := range value {
			c.attrMaps[mapName][ele.Name] = ele.Value
			log.Debugf("Added '%s' -> '%s' to LDAP map '%s'", ele.Name, ele.Value, mapName)
		}
	}
	c.TLS = &cfg.TLS
	c.CSP = csp
	log.Debug("LDAP client was successfully created")
	return c, nil
}

func cfgVal(val1, val2 string) string {
	if val1 != "" {
		return val1
	}
	return val2
}

// Client is an LDAP client
type Client struct {
	Host          string
	Port          int
	UseSSL        bool
	AdminDN       string
	AdminPassword string
	Base          string
	UserFilter    string               // e.g. "(uid=%s)"
	GroupFilter   string               // e.g. "(memberUid=%s)"
	attrNames     []string             // Names of attributes to request on an LDAP search
	attrExprs     map[string]*userExpr // Expressions to evaluate to get attribute value
	attrMaps      map[string]map[string]string
	AdminConn     *ldap.Conn
	TLS           *ctls.ClientTLSConfig
	CSP           bccsp.BCCSP
}

// GetUser returns a user object for username and attribute values
// for the requested attribute names
func (lc *Client) GetUser(username string, attrNames []string) (causer.User, error) {

	var sresp *ldap.SearchResult
	var err error

	log.Debugf("Getting user '%s'", username)

	// Search for the given username
	sreq := ldap.NewSearchRequest(
		lc.Base, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		lc.attrNames,
		nil,
	)

	// Try to search using the cached connection, if there is one
	conn := lc.AdminConn
	if conn != nil {
		log.Debugf("Searching for user '%s' using cached connection", username)
		sresp, err = conn.Search(sreq)
		if err != nil {
			log.Debugf("LDAP search failed but will close connection and try again; error was: %s", err)
			conn.Close()
			lc.AdminConn = nil
		}
	}

	// If there was no cached connection or the search failed for any reason
	// (including because the server may have closed the cached connection),
	// try with a new connection.
	if sresp == nil {
		log.Debugf("Searching for user '%s' using new connection", username)
		conn, err = lc.newConnection()
		if err != nil {
			return nil, err
		}
		sresp, err = conn.Search(sreq)
		if err != nil {
			conn.Close()
			return nil, errors.Wrapf(err, "LDAP search failure; search request: %+v", sreq)
		}
		// Cache the connection
		lc.AdminConn = conn
	}

	// Make sure there was exactly one match found
	if len(sresp.Entries) < 1 {
		return nil, errors.Errorf("User '%s' does not exist in LDAP directory", username)
	}
	if len(sresp.Entries) > 1 {
		return nil, errors.Errorf("Multiple users with name '%s' exist in LDAP directory", username)
	}

	entry := sresp.Entries[0]
	if entry == nil {
		return nil, errors.Errorf("No entry was returned for user '%s'", username)
	}

	// Construct the user object
	user := &user{
		name:   username,
		entry:  entry,
		client: lc,
	}

	log.Debugf("Successfully retrieved user '%s', DN: %s", username, entry.DN)

	return user, nil
}

// InsertUser inserts a user
func (lc *Client) InsertUser(user *causer.Info) error {
	return errNotSupported
}

// UpdateUser updates a user
func (lc *Client) UpdateUser(user *causer.Info, updatePass bool) error {
	return errNotSupported
}

// DeleteUser deletes a user
func (lc *Client) DeleteUser(id string) (causer.User, error) {
	return nil, errNotSupported
}

// GetAffiliation returns an affiliation group
func (lc *Client) GetAffiliation(name string) (spi.Affiliation, error) {
	return nil, errNotSupported
}

// GetAllAffiliations gets affiliation and any sub affiliation from the database
func (lc *Client) GetAllAffiliations(name string) (*sqlx.Rows, error) {
	return nil, errNotSupported
}

// GetRootAffiliation returns the root affiliation group
func (lc *Client) GetRootAffiliation() (spi.Affiliation, error) {
	return nil, errNotSupported
}

// InsertAffiliation adds an affiliation group
func (lc *Client) InsertAffiliation(name string, prekey string, version int) error {
	return errNotSupported
}

// DeleteAffiliation deletes an affiliation group
func (lc *Client) DeleteAffiliation(name string, force, identityRemoval, isRegistrar bool) (*causer.DbTxResult, error) {
	return nil, errNotSupported
}

// ModifyAffiliation renames the affiliation and updates all identities to use the new affiliation
func (lc *Client) ModifyAffiliation(oldAffiliation, newAffiliation string, force, isRegistrar bool) (*causer.DbTxResult, error) {
	return nil, errNotSupported
}

// GetUserLessThanLevel returns all identities that are less than the level specified
func (lc *Client) GetUserLessThanLevel(version int) ([]causer.User, error) {
	return nil, errNotSupported
}

// GetFilteredUsers returns all identities that fall under the affiliation and types
func (lc *Client) GetFilteredUsers(affiliation, types string) (*sqlx.Rows, error) {
	return nil, errNotSupported
}

// GetAffiliationTree returns the requested affiliations and all affiliations below it
func (lc *Client) GetAffiliationTree(name string) (*causer.DbTxResult, error) {
	return nil, errNotSupported
}

// Connect to the LDAP server and bind as user as admin user as specified in LDAP URL
func (lc *Client) newConnection() (conn *ldap.Conn, err error) {
	address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
	if !lc.UseSSL {
		log.Debug("Connecting to LDAP server over TCP")
		conn, err = ldap.Dial("tcp", address)
		if err != nil {
			return conn, errors.Wrapf(err, "Failed to connect to LDAP server over TCP at %s", address)
		}
	} else {
		log.Debug("Connecting to LDAP server over TLS")
		tlsConfig, err2 := ctls.GetClientTLSConfig(lc.TLS, lc.CSP)
		if err2 != nil {
			return nil, errors.WithMessage(err2, "Failed to get client TLS config")
		}

		tlsConfig.ServerName = lc.Host

		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
		if err != nil {
			return conn, errors.Wrapf(err, "Failed to connect to LDAP server over TLS at %s", address)
		}
	}
	// Bind with a read only user
	if lc.AdminDN != "" && lc.AdminPassword != "" {
		log.Debugf("Binding to the LDAP server as admin user %s", lc.AdminDN)
		err := conn.Bind(lc.AdminDN, lc.AdminPassword)
		if err != nil {
			return nil, errors.Wrapf(err, "LDAP bind failure as %s", lc.AdminDN)
		}
	}
	return conn, nil
}

// A user represents a single user or identity from LDAP
type user struct {
	name   string
	entry  *ldap.Entry
	client *Client
}

// GetName returns the user's enrollment ID, which is the DN (Distinquished Name)
func (u *user) GetName() string {
	return u.entry.DN
}

// GetType returns the type of the user
func (u *user) GetType() string {
	return "client"
}

// GetMaxEnrollments returns the max enrollments of the user
func (u *user) GetMaxEnrollments() int {
	return 0
}

// GetLevel returns the level of the user
func (u *user) GetLevel() int {
	return 0
}

// SetLevel sets the level of the user
func (u *user) SetLevel(level int) error {
	return errNotSupported
}

// Login logs a user in using password
func (u *user) Login(password string, caMaxEnrollment int) error {

	// Get a connection to use to bind over as the user to check the password
	conn, err := u.client.newConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Bind calls the LDAP server to check the user's password
	err = conn.Bind(u.entry.DN, password)
	if err != nil {
		return errors.Wrapf(err, "LDAP authentication failure for user '%s' (DN=%s)", u.name, u.entry.DN)
	}

	return nil

}

// LoginComplete requires no action on LDAP
func (u *user) LoginComplete() error {
	return nil
}

// GetAffiliationPath returns the affiliation path for this user.
// We convert the OU hierarchy to an array of strings, orderered
// from top-to-bottom.
func (u *user) GetAffiliationPath() []string {
	dn := u.entry.DN
	path := []string{}
	parts := strings.Split(dn, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if strings.HasPrefix(strings.ToUpper(p), "OU=") {
			path = append(path, strings.Trim(p[3:], " "))
		}
	}
	log.Debugf("Affilation path for DN '%s' is '%+v'", dn, path)
	return path
}

// GetAttribute returns the value of an attribute, or "" if not found
func (u *user) GetAttribute(name string) (*api.Attribute, error) {
	expr := u.client.attrExprs[name]
	if expr == nil {
		log.Debugf("Getting attribute '%s' from LDAP user '%s'", name, u.name)
		vals := u.entry.GetAttributeValues(name)
		if len(vals) == 0 {
			vals = make([]string, 0)
		}
		return &api.Attribute{Name: name, Value: strings.Join(vals, ",")}, nil
	}
	log.Debugf("Evaluating expression for attribute '%s' from LDAP user '%s'", name, u.name)
	value, err := expr.evaluate(u)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to evaluate LDAP expression")
	}
	return &api.Attribute{Name: name, Value: fmt.Sprintf("%v", value)}, nil
}

// GetAttributes returns the requested attributes
func (u *user) GetAttributes(attrNames []string) ([]api.Attribute, error) {
	attrs := []api.Attribute{}
	if attrNames == nil {
		attrNames = u.client.attrNames
	}
	for _, name := range attrNames {
		attr, err := u.GetAttribute(name)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, *attr)
	}
	for name := range u.client.attrExprs {
		attr, err := u.GetAttribute(name)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, *attr)
	}
	return attrs, nil
}

// Revoke is not supported for LDAP
func (u *user) Revoke() error {
	return errNotSupported
}

// IsRevoked is not supported for LDAP
func (u *user) IsRevoked() bool {
	return false
}

// ModifyAttributes adds a new attribute or modifies existing attribute
func (u *user) ModifyAttributes(attrs []api.Attribute) error {
	return errNotSupported
}

// IncrementIncorrectPasswordAttempts is not supported for LDAP
func (u *user) IncrementIncorrectPasswordAttempts() error {
	return errNotSupported
}

func (u *user) GetFailedLoginAttempts() int {
	return 0
}

// Returns a slice with the elements reversed
func reverse(in []string) []string {
	size := len(in)
	out := make([]string, size)
	for i := 0; i < size; i++ {
		out[i] = in[size-i-1]
	}
	return out
}

func newUserExpr(client *Client, attr, expr string) (*userExpr, error) {
	ue := &userExpr{client: client, attr: attr, expr: expr}
	err := ue.parse()
	if err != nil {
		return nil, err
	}
	return ue, nil
}

type userExpr struct {
	client     *Client
	attr, expr string
	eval       *govaluate.EvaluableExpression
	user       *user
}

func (ue *userExpr) parse() error {
	eval, err := govaluate.NewEvaluableExpression(ue.expr)
	if err == nil {
		// We were able to parse 'expr' without reference to any defined
		// functions, so we can reuse this evaluator across multiple users.
		ue.eval = eval
		return nil
	}
	// Try to parse 'expr' with defined functions
	_, err = govaluate.NewEvaluableExpressionWithFunctions(ue.expr, ue.functions())
	if err != nil {
		return errors.Wrapf(err, "Invalid expression for attribute '%s'", ue.attr)
	}
	return nil
}

func (ue *userExpr) evaluate(user *user) (interface{}, error) {
	var err error
	parms := map[string]interface{}{
		"DN":          user.entry.DN,
		"affiliation": user.GetAffiliationPath(),
	}
	eval := ue.eval
	if eval == nil {
		ue2 := &userExpr{
			client: ue.client,
			attr:   ue.attr,
			expr:   ue.expr,
			user:   user,
		}
		eval, err = govaluate.NewEvaluableExpressionWithFunctions(ue2.expr, ue2.functions())
		if err != nil {
			return nil, errors.Wrapf(err, "Invalid expression for attribute '%s'", ue.attr)
		}
	}
	result, err := eval.Evaluate(parms)
	if err != nil {
		log.Debugf("Error evaluating expression for attribute '%s'; parms: %+v; error: %+v", ue.attr, parms, err)
		return nil, err
	}
	log.Debugf("Evaluated expression for attribute '%s'; parms: %+v; result: %+v", ue.attr, parms, result)
	return result, nil
}

func (ue *userExpr) functions() map[string]govaluate.ExpressionFunction {
	return map[string]govaluate.ExpressionFunction{
		"attr": ue.attrFunction,
		"map":  ue.mapFunction,
		"if":   ue.ifFunction,
	}
}

// Get an LDAP attribute's value.
// The usage is:
//     attrFunction <attrName> [<separator>]
// If attribute <attrName> has multiple values, return the values in a single
// string separated by the <separator> string, which is a comma by default.
// Example:
//    Assume attribute "foo" has two values "bar1" and "bar2".
//    attrFunction("foo") returns "bar1,bar2"
//    attrFunction("foo",":") returns "bar1:bar2"
func (ue *userExpr) attrFunction(args ...interface{}) (interface{}, error) {
	if len(args) < 1 || len(args) > 2 {
		return nil, fmt.Errorf("Expecting 1 or 2 arguments for 'attr' but found %d", len(args))
	}
	attrName, ok := args[0].(string)
	if !ok {
		return nil, errors.Errorf("First argument to 'attr' must be a string; '%s' is not a string", args[0])
	}
	sep := ","
	if len(args) == 2 {
		sep, ok = args[1].(string)
		if !ok {
			return nil, errors.Errorf("Second argument to 'attr' must be a string; '%s' is not a string", args[1])
		}
	}
	vals := ue.user.entry.GetAttributeValues(attrName)
	log.Debugf("Values for LDAP attribute '%s' are '%+v'", attrName, vals)
	if len(vals) == 0 {
		vals = make([]string, 0)
	}
	return strings.Join(vals, sep), nil
}

// Map function performs string substitutions on the 1st argument for each
// entry in the map referenced by the 2nd argument.
//
// For example, assume that a user's LDAP attribute named 'myLDAPAttr' has
// three values: "foo1", "foo2", and "foo3".  Further assume the following
// LDAP configuration.
//
//    converters:
//       - name: myAttr
//         value: map(attr("myLDAPAttr"), myMap)
//    maps:
//       myMap:
//          foo1: bar1
//          foo2: bar2
//
// The value of the user's "myAttr" attribute is then "bar1,bar2,foo3".
// This value is computed as follows:
// 1) The value of 'attr("myLDAPAttr")' is "foo1,foo2,foo3" by joining
//    the values using the default separator character ",".
// 2) The value of 'map("foo1,foo2,foo3", "myMap")' is "foo1,foo2,foo3"
//    because it maps or substitutes "bar1" for "foo1" and "bar2" for "foo2"
//    according to the entries in the "myMap" map.
func (ue *userExpr) mapFunction(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, errors.Errorf("Expecting two arguments but found %d", len(args))
	}
	str, ok := args[0].(string)
	if !ok {
		return nil, errors.Errorf("First argument to 'map' must be a string; '%s' is not a string", args[0])
	}
	mapName := args[1].(string)
	if !ok {
		return nil, errors.Errorf("Second argument to 'map' must be a string; '%s' is not a string", args[1])
	}
	mapName = strings.ToLower(mapName)
	// Get the map
	maps := ue.client.attrMaps
	if maps == nil {
		return nil, errors.Errorf("No maps are defined; unknown map name: '%s'", mapName)
	}
	myMap := maps[mapName]
	if myMap == nil {
		return nil, errors.Errorf("Unknown map name: '%s'", mapName)
	}
	// Iterate through all of the entries in the map and perform string substitution
	// from the name to the value.
	for name, val := range myMap {
		str = strings.Replace(str, name, val, -1)
	}
	return str, nil
}

// The "ifFunction" returns the 2nd arg if the 1st boolean arg is true; otherwise it
// returns the 3rd arg.
func (ue *userExpr) ifFunction(args ...interface{}) (interface{}, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("Expecting 3 arguments for 'if' but found %d", len(args))
	}
	cond, ok := args[0].(bool)
	if !ok {
		return nil, errors.New("Expecting first argument to 'if' to be a boolean")
	}
	if cond {
		return args[1], nil
	}
	return args[2], nil
}
