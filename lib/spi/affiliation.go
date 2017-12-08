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

package spi

// affiliationImpl defines a group name and its parent
type affiliationImpl struct {
	Name   string `db:"name"`
	Prekey string `db:"prekey"`
	Level  int    `db:"level"`
}

// Affiliation is the API for a user's affiliation
type Affiliation interface {
	GetName() string
	GetPrekey() string
	GetLevel() int
}

// NewAffiliation returns an affiliationImpl object
func NewAffiliation(name, prekey string, level int) Affiliation {
	return &affiliationImpl{
		Name:   name,
		Prekey: prekey,
		Level:  level,
	}
}

// GetName returns the name of the affiliation
func (g *affiliationImpl) GetName() string {
	return g.Name
}

// GetPrekey returns the prekey of the affiliation
func (g *affiliationImpl) GetPrekey() string {
	return g.Prekey
}

// GetLevel returns the level of the affiliation
func (g *affiliationImpl) GetLevel() int {
	return g.Level
}
