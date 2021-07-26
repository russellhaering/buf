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

// Package bufbreakingv1 contains the VersionSpec for v1.
//
// It uses bufbreakingcheck and bufbreakingbuild.
//
// There were no changes from v1beta1.
package bufbreakingv1

import "github.com/bufbuild/buf/internal/buf/bufcheck/internal"

// VersionSpec is the version specification for v1.
//
// The only change from v1beta1 adds FILE_SAME_PACKAGE
// to PACKAGE, WIRE, and WIRE_JSON.
var VersionSpec = &internal.VersionSpec{
	RuleBuilders:      v1RuleBuilders,
	DefaultCategories: v1DefaultCategories,
	AllCategories:     v1AllCategories,
	IDToCategories:    v1IDToCategories,
}