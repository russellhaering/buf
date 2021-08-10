// Copyright 2020-2021 Buf Technologies, Inc.
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

// Code generated by protoc-gen-go-api. DO NOT EDIT.

package registryv1alpha1api

import (
	context "context"
	v1alpha1 "github.com/bufbuild/buf/internal/gen/proto/go/buf/alpha/registry/v1alpha1"
)

// DocService defines a set of APIs that are intended for use by bufwebd only.
// This is not intended for general use; changes and use cases are subject to executive approval.
type DocService interface {
	// GetSourceDirectoryInfo retrieves the directory and file structure for the
	// given owner, repository and reference.
	//
	// The purpose of this is to get a representation of the file tree for a given
	// module to enable exploring the module by navigating through its contents.
	GetSourceDirectoryInfo(
		ctx context.Context,
		owner string,
		repository string,
		reference string,
	) (root *v1alpha1.FileInfo, err error)
	// GetSourceFile retrieves the source contents for the given owner, repository,
	// reference, and path.
	GetSourceFile(
		ctx context.Context,
		owner string,
		repository string,
		reference string,
		path string,
	) (content []byte, err error)
	// GetModuleDocumentation retrieves the documentation for module based on the given
	// owner, repository, and reference.
	GetModuleDocumentation(
		ctx context.Context,
		owner string,
		repository string,
		reference string,
	) (moduleDocumentation *v1alpha1.ModuleDocumentation, err error)
	// GetPackageDocumentation retrieves a a slice of documentation structures
	// for the given owner, repository, reference, and package name.
	GetPackageDocumentation(
		ctx context.Context,
		owner string,
		repository string,
		reference string,
		packageName string,
	) (packageDocumentation *v1alpha1.PackageDocumentation, err error)
}
