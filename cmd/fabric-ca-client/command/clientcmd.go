/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	fabricCAClientProfileMode = "FABRIC_CA_CLIENT_PROFILE_MODE"
	extraArgsError            = "Unrecognized arguments found: %v\n\n%s"
)

const (
	client    = "client"
	enroll    = "enroll"
	reenroll  = "reenroll"
	register  = "register"
	revoke    = "revoke"
	getcacert = "getcacert"
	getcainfo = "getcainfo"
	gencsr    = "gencsr"
)

// Command interface initializes client command and loads an identity
type Command interface {
	// Initializes the client command configuration
	ConfigInit() error
	// Returns the name of the configuration file
	GetCfgFileName() string
	// Loads the credentials of an identity that are in the msp directory specified to this command
	LoadMyIdentity() (*lib.Identity, error)
	// Returns lib.ClientCfg instance associated with this comamnd
	GetClientCfg() *lib.ClientConfig
	// Returns viper instance associated with this comamnd
	GetViper() *viper.Viper
	// Returns the client's home directoty
	GetHomeDirectory() string
	// Set the default level to be something other than 'info'
	SetDefaultLogLevel(string)
}

type crlArgs struct {
	// Genenerate CRL with all the certificates that were revoked after this timestamp
	RevokedAfter string `help:"Generate CRL with certificates that were revoked after this UTC timestamp (in RFC3339 format)"`
	// Genenerate CRL with all the certificates that were revoked before this timestamp
	RevokedBefore string `help:"Generate CRL with certificates that were revoked before this UTC timestamp (in RFC3339 format)"`
	// Genenerate CRL with all the certificates that expire after this timestamp
	ExpireAfter string `help:"Generate CRL with certificates that expire after this UTC timestamp (in RFC3339 format)"`
	// Genenerate CRL with all the certificates that expire before this timestamp
	ExpireBefore string `help:"Generate CRL with certificates that expire before this UTC timestamp (in RFC3339 format)"`
}

type revokeArgs struct {
	// GenCRL specifies whether to generate a CRL
	GenCRL bool `def:"false" json:"gencrl,omitempty" opt:"" help:"Generates a CRL that contains all revoked certificates"`
}

// ClientCmd encapsulates cobra command that provides command line interface
// for the Fabric CA client and the configuration used by the Fabric CA client
type ClientCmd struct {
	// name of the sub command
	name string
	// rootCmd is the base command for the Hyerledger Fabric CA client
	rootCmd *cobra.Command
	// My viper instance
	myViper *viper.Viper
	// cfgFileName is the name of the configuration file
	cfgFileName string
	// homeDirectory is the location of the client's home directory
	homeDirectory string
	// clientCfg is the client's configuration
	clientCfg *lib.ClientConfig
	// cfgAttrs are the attributes specified via flags or env variables
	// and translated to Attributes field in registration
	cfgAttrs []string
	// cfgAttrReqs are the attribute requests specified via flags or env variables
	// and translated to the AttrReqs field in enrollment
	cfgAttrReqs []string
	// cfgCsrNames are the certificate signing request names specified via flags
	// or env variables
	cfgCsrNames []string
	// csrCommonName is the certificate signing request common name specified via the flag
	csrCommonName string
	// gencrl command argument values
	crlParams crlArgs
	// revoke command argument values
	revokeParams revokeArgs
	// profileMode is the profiling mode, cpu or mem or empty
	profileMode string
	// profileInst is the profiling instance object
	profileInst interface {
		Stop()
	}
	// Dynamically configuring identities
	dynamicIdentity identityArgs
	// Dynamically configuring affiliations
	dynamicAffiliation affiliationArgs
	// Set to log level
	logLevel string
}

// NewCommand returns new ClientCmd ready for running
func NewCommand(name string) *ClientCmd {
	c := &ClientCmd{
		myViper: viper.New(),
	}
	c.name = strings.ToLower(name)
	c.init()
	return c
}

// Execute runs this ClientCmd
func (c *ClientCmd) Execute() error {
	return c.rootCmd.Execute()
}

// init initializes the ClientCmd instance
// It intializes the cobra root and sub commands and
// registers command flgs with viper
func (c *ClientCmd) init() {
	c.rootCmd = &cobra.Command{
		Use:   cmdName,
		Short: longName,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := c.checkAndEnableProfiling()
			if err != nil {
				return err
			}
			util.CmdRunBegin(c.myViper)
			cmd.SilenceUsage = true
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if c.profileMode != "" && c.profileInst != nil {
				c.profileInst.Stop()
			}
			return nil
		},
	}
	c.rootCmd.AddCommand(c.newRegisterCommand(),
		newEnrollCmd(c).getCommand(),
		c.newReenrollCommand(),
		c.newRevokeCommand(),
		newGetCAInfoCmd(c).getCommand(),
		c.newGenCsrCommand(),
		c.newGenCRLCommand(),
		c.newIdentityCommand(),
		c.newAffiliationCommand(),
		createCertificateCommand(c))
	c.rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Prints Fabric CA Client version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(metadata.GetVersionInfo(cmdName))
		},
	})
	c.registerFlags()
	log.Level = log.LevelInfo
}

// registerFlags registers command flags with viper
func (c *ClientCmd) registerFlags() {
	// Get the default config file path
	cfg := util.GetDefaultConfigFile(cmdName)

	// All env variables must be prefixed
	c.myViper.SetEnvPrefix(envVarPrefix)
	c.myViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	host, err := os.Hostname()
	if err != nil {
		log.Error(err)
	}

	// Set global flags used by all commands
	pflags := c.rootCmd.PersistentFlags()
	pflags.StringVarP(&c.cfgFileName, "config", "c", "", "Configuration file")
	pflags.MarkHidden("config")
	// Don't want to use the default parameter for StringVarP. Need to be able to identify if home directory was explicitly set
	pflags.StringVarP(&c.homeDirectory, "home", "H", "", fmt.Sprintf("Client's home directory (default \"%s\")", filepath.Dir(cfg)))
	pflags.StringSliceVarP(
		&c.cfgAttrs, "id.attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	pflags.StringSliceVarP(
		&c.cfgAttrReqs, "enrollment.attrs", "", nil, "A list of comma-separated attribute requests of the form <name>[:opt] (e.g. foo,bar:opt)")
	util.FlagString(c.myViper, pflags, "myhost", "m", host,
		"Hostname to include in the certificate signing request during enrollment")
	pflags.StringSliceVarP(
		&c.cfgCsrNames, "csr.names", "", nil, "A list of comma-separated CSR names of the form <name>=<value> (e.g. C=CA,O=Org1)")

	c.clientCfg = &lib.ClientConfig{}
	tags := map[string]string{
		"help.csr.cn":                "The common name field of the certificate signing request",
		"help.csr.serialnumber":      "The serial number in a certificate signing request",
		"help.csr.hosts":             "A list of comma-separated host names in a certificate signing request",
		"skip.csp.pluginopts.config": "true", // Skipping because this a map
	}
	err = util.RegisterFlags(c.myViper, pflags, c.clientCfg, tags)
	if err != nil {
		panic(err)
	}
}

// checkAndEnableProfiling checks for the FABRIC_CA_CLIENT_PROFILE_MODE
// env variable, if it is set to "cpu", cpu profiling is enbled;
// if it is set to "heap", heap profiling is enabled
func (c *ClientCmd) checkAndEnableProfiling() error {
	c.profileMode = strings.ToLower(os.Getenv(fabricCAClientProfileMode))
	if c.profileMode != "" {
		wd, err := os.Getwd()
		if err != nil {
			wd = os.Getenv("HOME")
		}
		opt := profile.ProfilePath(wd)
		switch c.profileMode {
		case "cpu":
			c.profileInst = profile.Start(opt, profile.CPUProfile)
		case "heap":
			c.profileInst = profile.Start(opt, profile.MemProfileRate(2048))
		default:
			msg := fmt.Sprintf("Invalid value for the %s environment variable; found '%s', expecting 'cpu' or 'heap'",
				fabricCAClientProfileMode, c.profileMode)
			return errors.New(msg)
		}
	}
	return nil
}

// Certain client commands can only be executed if enrollment credentials
// are present
func (c *ClientCmd) requiresEnrollment() bool {
	return c.name != enroll && c.name != getcacert && c.name != getcainfo && c.name != gencsr
}

// Create default client configuration file only during an enroll or gencsr command
func (c *ClientCmd) shouldCreateDefaultConfig() bool {
	return c.name == enroll || c.name == gencsr
}

func (c *ClientCmd) requiresUser() bool {
	return c.name != gencsr
}

// LoadMyIdentity loads the client's identity
func (c *ClientCmd) LoadMyIdentity() (*lib.Identity, error) {
	client := &lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return nil, err
	}

	return id, nil
}

// GetClientCfg returns client configuration
func (c *ClientCmd) GetClientCfg() *lib.ClientConfig {
	return c.clientCfg
}

// GetCfgFileName returns name of the client command configuration file
func (c *ClientCmd) GetCfgFileName() string {
	return c.cfgFileName
}

// GetViper returns the viper instance
func (c *ClientCmd) GetViper() *viper.Viper {
	return c.myViper
}

// SetDefaultLogLevel sets the default log level for a command to a specific level
func (c *ClientCmd) SetDefaultLogLevel(logLevel string) {
	c.logLevel = logLevel
}
