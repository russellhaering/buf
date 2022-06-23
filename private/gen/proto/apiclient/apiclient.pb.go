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

// Code generated by protoc-gen-go-apiclient. DO NOT EDIT.

package apiclient

import (
	registryv1alpha1apiclient "github.com/bufbuild/buf/private/gen/proto/apiclient/buf/alpha/registry/v1alpha1/registryv1alpha1apiclient"
)

type TokenConfig struct {
	Token      string
	Reader     func(string) (string, error)
	AuthHeader string
	AuthPrefix string
}

func NewTokenConfig(header string, prefix string, token string) TokenConfig {
	return TokenConfig{
		Token:      token,
		AuthHeader: header,
		AuthPrefix: prefix,
	}
}

func NewTokenConfigWithReader(header string, prefix string, reader func(string) (string, error)) TokenConfig {
	return TokenConfig{
		Reader:     reader,
		AuthHeader: header,
		AuthPrefix: prefix,
	}
}

// Provider provides all Providers.
type Provider interface {
	BufAlphaRegistryV1alpha1() registryv1alpha1apiclient.Provider
}
