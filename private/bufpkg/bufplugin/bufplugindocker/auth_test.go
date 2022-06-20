// Copyright 2020-2022 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bufplugindocker

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryAuth_MarshalJSON(t *testing.T) {
	auth := RegistryAuth{
		Username:      "someuser",
		Password:      "somepass",
		Email:         "someemail@buf.build",
		ServerAddress: "plugins.buf.build",
	}
	encoded, err := json.Marshal(auth)
	require.NoError(t, err)
	var decoded RegistryAuth
	err = json.Unmarshal(encoded, &decoded)
	require.NoError(t, err)
	assert.Equal(t, auth, decoded)
}

func TestRegistryAuth_ToFromHeader(t *testing.T) {
	auth := RegistryAuth{
		Username:      "someuser",
		Password:      "somepass",
		Email:         "someemail@buf.build",
		ServerAddress: "plugins.buf.build",
	}
	encoded, err := auth.ToHeader()
	require.NoError(t, err)
	var decoded RegistryAuth
	err = decoded.FromHeader(encoded)
	require.NoError(t, err)
	assert.Equal(t, auth, decoded)
}
