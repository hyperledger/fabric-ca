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

package server

import (
	"errors"
)

var (
	errNoAuthHdr           = errors.New("No Authorization header was found")
	errNoBasicAuthHdr      = errors.New("No Basic Authorization header was found")
	errNoTokenAuthHdr      = errors.New("No Token Authorization header was found")
	errBasicAuthNotAllowed = errors.New("Basic authorization is not permitted")
	errTokenAuthNotAllowed = errors.New("Token authorization is not permitted")
	errInvalidUserPass     = errors.New("Invalid user name or password")
	errInputNotSeeker      = errors.New("Input stream was not a seeker")
)
