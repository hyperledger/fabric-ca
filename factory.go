/*
 * This file is simply a mirror of the interfaces in interfaces/interfaces.go.
 * This was done in order to prevent an import cycle.
 */

package cop

import (
  "github.com/hyperledger/fabric-cop/idp"
  def "github.com/hyperledger/fabric-cop/lib/defaultImpl"
)

// NewClient creates a COP client
func NewClient(config string) (idp.ClientAPI, error) {
   return def.NewClient(config)
}
