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

package main

import (
	"fmt"
	"os"
	"testing"
	"time"
)

const (
	CERT string = "../../testdata/cop-cert.pem"
	KEY  string = "../../testdata/cop-key.pem"
	CFG  string = "../../testdata/cop.json"
	CSR  string = "../../testdata/csr.json"
	REG  string = "../../testdata/registerRequest.json"
)

var serverStarted bool
var serverExitCode = 0

// Test the server start command
func TestStartServer(t *testing.T) {
	rtn := startServer()
	if rtn != 0 {
		t.Errorf("Failed to start server with return code: %d", rtn)
		t.FailNow()
	}
}

// func TestEnroll(t *testing.T) {
// 	rtn := enroll("admin", "adminpw")
// 	if rtn != 0 {
// 		t.Errorf("Failed to enroll with return code: %d", rtn)
// 	}
// }

func TestRegister(t *testing.T) {
	rtn := register(REG)
	if rtn != 0 {
		t.Errorf("Failed to register with return code: %d", rtn)
	}
}

func startServer() int {
	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		go runServer()
		time.Sleep(3 * time.Second)
		fmt.Println("COP server started")
	} else {
		fmt.Println("COP server already started")
	}
	return serverExitCode
}

func runServer() {
	os.Setenv("COP_DEBUG", "true")
	serverExitCode = COPMain([]string{"cop", "server", "start", "-ca", CERT, "-ca-key", KEY, "-config", CFG})
}

func enroll(user, pass string) int {
	fmt.Printf("enrolling user '%s' with password '%s' ...\n", user, pass)
	rtn := COPMain([]string{"cop", "client", "enroll", user, pass, CSR, "http://localhost:8888", "loglevel=0"})
	fmt.Printf("enroll result is '%d'\n", rtn)
	return rtn
}

func register(file string) int {
	fmt.Printf("register file '%s' ...\n", file)
	rtn := COPMain([]string{"cop", "client", "register", file, "keith", "http://localhost:8888", "loglevel=0"})
	fmt.Printf("register result is '%d'\n", rtn)
	return rtn
}
