/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"fmt"
	"net/http"
	"os"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/hyperledger/fabric-ca/lib/server/certificaterequest"
	cadbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

type certPEM struct {
	PEM string `db:"pem"`
}

func newCertificateEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Path:      "certificates",
		Methods:   []string{"GET", "DELETE"},
		Handler:   certificatesHandler,
		Server:    s,
		successRC: 200,
	}
}

func certificatesHandler(ctx *serverRequestContextImpl) (interface{}, error) {
	var err error
	// Process Request
	err = processCertificateRequest(ctx)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// processCertificateRequest will process the certificate request
func processCertificateRequest(ctx ServerRequestContext) error {
	log.Debug("Processing certificate request")
	var err error

	// Authenticate
	_, err = ctx.TokenAuthentication()
	if err != nil {
		return err
	}

	// Perform authority checks to make sure that caller has the correct
	// set of attributes to manage certificates
	err = authChecks(ctx)
	if err != nil {
		return err
	}

	method := ctx.GetReq().Method
	switch method {
	case "GET":
		return processGetCertificateRequest(ctx)
	case "DELETE":
		return errors.New("DELETE Not Implemented")
	default:
		return errors.Errorf("Invalid request: %s", method)
	}
}

// authChecks verifies that the caller has either attribute "hf.Registrar.Roles"
// or "hf.Revoker" with a value of true
func authChecks(ctx ServerRequestContext) error {
	log.Debug("Performing attribute authorization checks for certificates endpoint")

	caller, err := ctx.GetCaller()
	if err != nil {
		return err
	}

	_, err = caller.GetAttribute("hf.Registrar.Roles")
	if err != nil {
		err = ctx.HasRole("hf.Revoker")
		if err != nil {
			return caerrors.NewAuthorizationErr(caerrors.ErrAuthorizationFailure, "Caller does not posses either hf.Registrar.Roles or hf.Revoker attribute")
		}
	}

	return nil
}

func processGetCertificateRequest(ctx ServerRequestContext) error {
	log.Debug("Processing GET certificate request")
	var err error

	req, err := certificaterequest.NewCertificateRequest(ctx)
	if err != nil {
		return caerrors.NewHTTPErr(400, caerrors.ErrGettingCert, "Invalid Request: %s", err)
	}

	// Execute DB query and stream response
	err = getCertificates(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

// getCertificates executes the DB query and streams the results to client
func getCertificates(ctx ServerRequestContext, req *certificaterequest.Impl) error {
	w := ctx.GetResp()
	flusher, _ := w.(http.Flusher)

	caller, err := ctx.GetCaller()
	if err != nil {
		return err
	}

	// Execute DB query
	rows, err := ctx.GetCertificates(req, cadbuser.GetAffiliation(caller))
	if err != nil {
		return err
	}
	defer rows.Close()

	// Get the number of certificates to return back to client in a chunk based on the environment variable
	// If environment variable not set, default to 100 certificates
	numCerts, err := ctx.ChunksToDeliver(os.Getenv("FABRIC_CA_SERVER_MAX_CERTS_PER_CHUNK"))
	if err != nil {
		return err
	}
	log.Debugf("Number of certs to be delivered in each chunk: %d", numCerts)

	w.Write([]byte(`{"certs":[`))

	rowNumber := 0
	for rows.Next() {
		rowNumber++
		var cert certPEM
		err := rows.StructScan(&cert)
		if err != nil {
			return caerrors.NewHTTPErr(500, caerrors.ErrGettingCert, "Failed to get read row: %s", err)
		}

		if rowNumber > 1 {
			w.Write([]byte(","))
		}

		resp, err := util.Marshal(cert, "certificate")
		if err != nil {
			return caerrors.NewHTTPErr(500, caerrors.ErrGettingCert, "Failed to marshal certificate: %s", err)
		}
		w.Write(resp)

		// If hit the number of identities requested then flush
		if rowNumber%numCerts == 0 {
			flusher.Flush() // Trigger "chunked" encoding and send a chunk...
		}
	}

	log.Debug("Number of certificates found: ", rowNumber)

	// Close the JSON object
	caname := ctx.GetQueryParm("ca")
	w.Write([]byte(fmt.Sprintf("], \"caname\":\"%s\"}", caname)))
	flusher.Flush()

	return nil
}
