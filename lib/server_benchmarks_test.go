/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package lib

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	serverbPort       = 7061
	revokeUserCertEnv = "REVOKE_USER_CERT"
	clientMspDir      = testdataDir + "/msp"
)

func BenchmarkServerStart(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		srv := getServerForBenchmark(serverbPort, rootDir, "", -1, b)
		b.StartTimer()
		err := srv.Start()
		b.StopTimer()
		if err != nil {
			b.Fatalf("Server failed to start: %v", err)
		}
		srv.Stop()
		os.RemoveAll(rootDir)
	}
}

func BenchmarkGetCACert(b *testing.B) {
	// Stop the timer and perform all the initialization
	b.StopTimer()
	srv := getServerForBenchmark(serverbPort, rootDir, "", -1, b)
	err := srv.Start()
	if err != nil {
		b.Fatalf("Server failed to start: %v", err)
	}
	defer cleanup(srv)

	client := getTestClient(serverbPort)
	infoSE := newCAInfoEndpoint(srv)
	for i := 0; i < b.N; i++ {
		req, err := createGetCACertRequest(client)
		if err != nil {
			b.Fatalf("Failed to create getCACert request: %s", err)
		}
		rw := httptest.NewRecorder()
		// Start the timer now to measure getCACert handler
		b.StartTimer()
		infoSE.ServeHTTP(rw, req)
		// Stop the timer
		b.StopTimer()
		resp := rw.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			b.Fatalf("GetCACert request handler returned an error: %s", body)
		}
	}
}

func BenchmarkRegister(b *testing.B) {
	b.StopTimer()
	srv := getServerForBenchmark(serverbPort, rootDir, "", -1, b)
	err := srv.Start()
	if err != nil {
		b.Fatalf("Server failed to start: %v", err)
	}
	defer cleanup(srv)

	client := getTestClient(serverbPort)
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		b.Fatalf("Failed to enroll admin/adminpw: %s", err)
	}

	admin := eresp.Identity
	registerSE := newRegisterEndpoint(srv)
	for i := 0; i < b.N; i++ {
		req, err := createRegisterRequest(admin, "registeruser"+strconv.Itoa(i))
		if err != nil {
			b.Fatalf("Failed to create registration request: %s", err)
		}
		rw := httptest.NewRecorder()
		b.StartTimer()
		registerSE.ServeHTTP(rw, req)
		b.StopTimer()
		resp := rw.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			b.Fatalf("Register request handler returned an error: %s", body)
		}
	}
}

func BenchmarkEnroll(b *testing.B) {
	b.StopTimer()
	srv := getServerForBenchmark(serverbPort, rootDir, "", -1, b)
	err := srv.Start()
	if err != nil {
		b.Fatalf("Server failed to start: %v", err)
	}
	defer cleanup(srv)

	client := getTestClient(serverbPort)
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		b.Fatalf("Failed to enroll admin/adminpw: %s", err)
	}
	admin := eresp.Identity
	enrollSE := newEnrollEndpoint(srv)
	for i := 0; i < b.N; i++ {
		userName := "enrolluser" + strconv.Itoa(i)
		regReq := &api.RegistrationRequest{
			Name:        userName,
			Type:        "user",
			Affiliation: "hyperledger.fabric.security",
		}
		regRes, err := admin.Register(regReq)
		if err != nil {
			b.Fatalf("Failed to register user %s: %s", userName, err)
		}
		req, err := createEnrollRequest(admin, userName, regRes)
		if err != nil {
			b.Fatalf("Failed to create enrollment request: %s", err)
		}
		rw := httptest.NewRecorder()
		b.StartTimer()
		enrollSE.ServeHTTP(rw, req)
		b.StopTimer()
		resp := rw.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			b.Fatalf("Enroll request handler returned an error: %s", body)
		}
	}
}

func BenchmarkReenrollOneUser(b *testing.B) {
	b.StopTimer()
	srv := getServerForBenchmark(serverbPort, rootDir, "", -1, b)
	err := srv.Start()
	if err != nil {
		b.Fatalf("Server failed to start: %v", err)
	}
	defer cleanup(srv)

	client := getTestClient(serverbPort)
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		b.Fatalf("Failed to enroll admin/adminpw: %s", err)
	}
	admin := eresp.Identity
	userName := "reenrolluser0"
	regReq := &api.RegistrationRequest{
		Name:        userName,
		Type:        "user",
		Affiliation: "hyperledger.fabric.security",
	}
	user, err := admin.RegisterAndEnroll(regReq)
	if err != nil {
		b.Fatalf("Failed to register and enroll the user %s: %s", userName, err)
	}
	reenrollSE := newReenrollEndpoint(srv)
	for i := 0; i < b.N; i++ {
		req, err := createReenrollRequest(user)
		if err != nil {
			b.Fatalf("Failed to create reenroll request: %s", err)
		}
		rw := httptest.NewRecorder()
		b.StartTimer()
		reenrollSE.ServeHTTP(rw, req)
		b.StopTimer()
		resp := rw.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			b.Fatalf("Reenroll request handler returned an error: %s", body)
		}
	}
}

func BenchmarkReenroll(b *testing.B) {
	b.StopTimer()
	srv := getServerForBenchmark(serverbPort, rootDir, "", -1, b)
	err := srv.Start()
	if err != nil {
		b.Fatalf("Server failed to start: %v", err)
	}
	defer cleanup(srv)

	client := getTestClient(serverbPort)
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		b.Fatalf("Failed to enroll admin/adminpw: %s", err)
	}
	admin := eresp.Identity
	reenrollSE := newReenrollEndpoint(srv)
	for i := 0; i < b.N; i++ {
		userName := "reenrollusers" + strconv.Itoa(i)
		regReq := &api.RegistrationRequest{
			Name:        userName,
			Type:        "user",
			Affiliation: "hyperledger.fabric.security",
		}
		user, err := admin.RegisterAndEnroll(regReq)
		if err != nil {
			b.Fatalf("Failed to register and enroll the user %s: %s", userName, err)
		}
		req, err := createReenrollRequest(user)
		if err != nil {
			b.Fatalf("Failed to create reenroll request: %s", err)
		}
		rw := httptest.NewRecorder()
		b.StartTimer()
		reenrollSE.ServeHTTP(rw, req)
		b.StopTimer()
		resp := rw.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			b.Fatalf("Reenroll request handler returned an error: %s", body)
		}
	}
}

func BenchmarkRevokeUserCert(b *testing.B) {
	b.StopTimer()
	revokeUserCertOrig := os.Getenv(revokeUserCertEnv)
	os.Setenv(revokeUserCertEnv, "true")
	defer os.Setenv(revokeUserCertEnv, revokeUserCertOrig)
	invokeRevokeBenchmark(b)
}

func BenchmarkRevokeIdentity(b *testing.B) {
	b.StopTimer()
	revokeUserCertOrig := os.Getenv(revokeUserCertEnv)
	os.Setenv(revokeUserCertEnv, "")
	defer os.Setenv(revokeUserCertEnv, revokeUserCertOrig)
	invokeRevokeBenchmark(b)
}

func BenchmarkGenCRL(b *testing.B) {
	b.StopTimer()
	srv := getServerForBenchmark(serverbPort, rootDir, "", -1, b)
	err := srv.Start()
	if err != nil {
		b.Fatalf("Server failed to start: %v", err)
	}
	defer cleanup(srv)

	client := getTestClient(serverbPort)
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		b.Fatalf("Failed to enroll admin/adminpw: %s", err)
	}
	admin := eresp.Identity

	for j := 0; j < 50; j++ {
		userName := "gencrluser" + strconv.Itoa(j)
		regReq := &api.RegistrationRequest{
			Name:        userName,
			Type:        "user",
			Affiliation: "hyperledger.fabric.security",
		}
		_, err = admin.RegisterAndEnroll(regReq)
		if err != nil {
			b.Fatalf("Failed to register and enroll the user %s: %s", userName, err)
		}
		_, err = admin.Revoke(&api.RevocationRequest{
			Name: userName,
		})
		if err != nil {
			b.Fatalf("Failed to revoke the user %s: %s", userName, err)
		}
	}

	genCRLSE := newGenCRLEndpoint(srv)

	for i := 0; i < b.N; i++ {
		req, err := createGenCRLRequest(admin)
		if err != nil {
			b.Fatalf("Failed to create the genCRL request %s", err)
		}
		rw := httptest.NewRecorder()
		b.StartTimer()
		genCRLSE.ServeHTTP(rw, req)
		b.StopTimer()
		resp := rw.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			b.Fatalf("GenCRL request handler returned an error: %s", body)
		}
	}
}

func invokeRevokeBenchmark(b *testing.B) {
	srv := getServerForBenchmark(serverbPort, rootDir, "", -1, b)
	err := srv.Start()
	if err != nil {
		b.Fatalf("Server failed to start: %v", err)
	}
	defer cleanup(srv)

	client := getTestClient(serverbPort)
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		b.Fatalf("Failed to enroll admin/adminpw: %s", err)
	}
	admin := eresp.Identity
	revokeSE := newRevokeEndpoint(srv)
	for i := 0; i < b.N; i++ {
		userName := "revokeuser" + strconv.Itoa(i)
		regReq := &api.RegistrationRequest{
			Name:        userName,
			Type:        "user",
			Affiliation: "hyperledger.fabric.security",
		}
		user, err := admin.RegisterAndEnroll(regReq)
		if err != nil {
			b.Fatalf("Failed to register and enroll user %s: %s", userName, err)
		}
		req, err := createRevokeRequest(admin, user)
		if err != nil {
			b.Fatalf("Failed to create revoke request %s", err)
		}
		rw := httptest.NewRecorder()
		b.StartTimer()
		revokeSE.ServeHTTP(rw, req)
		b.StopTimer()
		resp := rw.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			b.Fatalf("Revoke request handler returned an error: %s", body)
		}
	}
}

func cleanup(srv *Server) {
	srv.Stop()
	os.RemoveAll(rootDir)
	os.RemoveAll(clientMspDir)
}

func createRevokeRequest(admin *Identity, user *Identity) (*http.Request, error) {
	revokeReq := &api.RevocationRequest{}
	serial, aki, err := GetCertID(user.GetECert().Cert())
	if err != nil {
		return nil, err
	}
	revokeUserCert := os.Getenv(revokeUserCertEnv)
	if revokeUserCert == "" {
		revokeReq.Name = user.GetName()
	} else {
		revokeReq.AKI = aki
		revokeReq.Serial = serial
	}
	body, err := util.Marshal(revokeReq, "RevocationRequest")
	if err != nil {
		return nil, err
	}
	req, err := admin.client.newPost("revoke", body)
	if err != nil {
		return nil, err
	}
	err = admin.addTokenAuthHdr(req, body)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func createReenrollRequest(user *Identity) (*http.Request, error) {
	csr := &user.client.Config.CSR
	csrPEM, _, err := user.client.GenCSR(csr, user.GetName())
	if err != nil {
		return nil, err
	}
	reqNet := &api.ReenrollmentRequestNet{
		CAName: user.client.Config.CAName,
	}

	// Get the body of the request
	if csr != nil {
		reqNet.SignRequest.Hosts = csr.Hosts
	}
	reqNet.SignRequest.Request = string(csrPEM)
	reqNet.SignRequest.Profile = user.client.Config.Enrollment.Profile
	reqNet.SignRequest.Label = user.client.Config.Enrollment.Label

	body, err := util.Marshal(reqNet, "SignRequest")
	if err != nil {
		return nil, err
	}
	req, err := user.client.newPost("reenroll", body)
	if err != nil {
		return nil, err
	}
	err = user.addTokenAuthHdr(req, body)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func createEnrollRequest(admin *Identity, userName string, regRes *api.RegistrationResponse) (*http.Request, error) {
	// Generate the CSR
	csr := &admin.client.Config.CSR
	csr.CN = userName
	csrPEM, _, err := admin.client.GenCSR(csr, userName)
	if err != nil {
		return nil, err
	}

	reqNet := &api.EnrollmentRequestNet{
		CAName: "",
	}

	if csr != nil {
		reqNet.SignRequest.Hosts = csr.Hosts
	}
	reqNet.SignRequest.Request = string(csrPEM)
	reqNet.SignRequest.Profile = admin.client.Config.Enrollment.Profile
	reqNet.SignRequest.Label = admin.client.Config.Enrollment.Label

	body, err := util.Marshal(reqNet, "SignRequest")
	if err != nil {
		return nil, err
	}

	// Send the CSR to the fabric-ca server with basic auth header
	req, err := admin.client.newPost("enroll", body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(userName, regRes.Secret)
	return req, nil
}

func createRegisterRequest(admin *Identity, userName string) (*http.Request, error) {
	regReq := &api.RegistrationRequest{
		Name:        userName,
		Type:        "user",
		Affiliation: "hyperledger.fabric.security",
	}
	reqBody, err := util.Marshal(regReq, "RegistrationRequest")
	if err != nil {
		return nil, err
	}
	req, err := admin.client.newPost("register", reqBody)
	if err != nil {
		return nil, err
	}
	err = admin.addTokenAuthHdr(req, reqBody)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func createGetCACertRequest(client *Client) (*http.Request, error) {
	body, err := util.Marshal(&api.GetCAInfoRequest{}, "GetCAInfo")
	if err != nil {
		return nil, err
	}
	cainforeq, err := client.newPost("cainfo", body)
	if err != nil {
		return nil, err
	}
	return cainforeq, nil
}

func createGenCRLRequest(user *Identity) (*http.Request, error) {
	body, err := util.Marshal(&api.GenCRLRequest{CAName: ""}, "GenCRL")
	if err != nil {
		return nil, err
	}
	req, err := user.client.newPost("gencrl", body)
	if err != nil {
		return nil, err
	}
	err = user.addTokenAuthHdr(req, body)
	if err != nil {
		return nil, err
	}
	return req, nil
}
