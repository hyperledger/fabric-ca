package client

import (
	cop "github.com/hyperledger/fabric-cop"
	"github.com/hyperledger/fabric-cop/idp"
)

// NewClient returns a client given a serverAddr
func NewClient(serverAddr string) (idp.ClientAPI, error) {
	return cop.NewClient(`{"serverAddr":"` + serverAddr + `"}`)
}
