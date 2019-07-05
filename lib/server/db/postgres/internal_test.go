/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

func (p *Postgres) Datasource() string {
	return p.datasource
}
