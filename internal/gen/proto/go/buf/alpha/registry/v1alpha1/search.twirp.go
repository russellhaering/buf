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

// Code generated by protoc-gen-twirp v8.1.0, DO NOT EDIT.
// source: buf/alpha/registry/v1alpha1/search.proto

package registryv1alpha1

import context "context"
import fmt "fmt"
import http "net/http"
import ioutil "io/ioutil"
import json "encoding/json"
import strconv "strconv"
import strings "strings"

import protojson "google.golang.org/protobuf/encoding/protojson"
import proto "google.golang.org/protobuf/proto"
import twirp "github.com/twitchtv/twirp"
import ctxsetters "github.com/twitchtv/twirp/ctxsetters"

// Version compatibility assertion.
// If the constant is not defined in the package, that likely means
// the package needs to be updated to work with this generated code.
// See https://twitchtv.github.io/twirp/docs/version_matrix.html
const _ = twirp.TwirpPackageMinVersion_8_1_0

// =======================
// SearchService Interface
// =======================

// SearchService is the search service.
type SearchService interface {
	// Search searches the BSR.
	Search(context.Context, *SearchRequest) (*SearchResponse, error)
}

// =============================
// SearchService Protobuf Client
// =============================

type searchServiceProtobufClient struct {
	client      HTTPClient
	urls        [1]string
	interceptor twirp.Interceptor
	opts        twirp.ClientOptions
}

// NewSearchServiceProtobufClient creates a Protobuf client that implements the SearchService interface.
// It communicates using Protobuf and can be configured with a custom HTTPClient.
func NewSearchServiceProtobufClient(baseURL string, client HTTPClient, opts ...twirp.ClientOption) SearchService {
	if c, ok := client.(*http.Client); ok {
		client = withoutRedirects(c)
	}

	clientOpts := twirp.ClientOptions{}
	for _, o := range opts {
		o(&clientOpts)
	}

	// Using ReadOpt allows backwards and forwads compatibility with new options in the future
	literalURLs := false
	_ = clientOpts.ReadOpt("literalURLs", &literalURLs)
	var pathPrefix string
	if ok := clientOpts.ReadOpt("pathPrefix", &pathPrefix); !ok {
		pathPrefix = "/twirp" // default prefix
	}

	// Build method URLs: <baseURL>[<prefix>]/<package>.<Service>/<Method>
	serviceURL := sanitizeBaseURL(baseURL)
	serviceURL += baseServicePath(pathPrefix, "buf.alpha.registry.v1alpha1", "SearchService")
	urls := [1]string{
		serviceURL + "Search",
	}

	return &searchServiceProtobufClient{
		client:      client,
		urls:        urls,
		interceptor: twirp.ChainInterceptors(clientOpts.Interceptors...),
		opts:        clientOpts,
	}
}

func (c *searchServiceProtobufClient) Search(ctx context.Context, in *SearchRequest) (*SearchResponse, error) {
	ctx = ctxsetters.WithPackageName(ctx, "buf.alpha.registry.v1alpha1")
	ctx = ctxsetters.WithServiceName(ctx, "SearchService")
	ctx = ctxsetters.WithMethodName(ctx, "Search")
	caller := c.callSearch
	if c.interceptor != nil {
		caller = func(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
			resp, err := c.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*SearchRequest)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*SearchRequest) when calling interceptor")
					}
					return c.callSearch(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*SearchResponse)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*SearchResponse) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}
	return caller(ctx, in)
}

func (c *searchServiceProtobufClient) callSearch(ctx context.Context, in *SearchRequest) (*SearchResponse, error) {
	out := new(SearchResponse)
	ctx, err := doProtobufRequest(ctx, c.client, c.opts.Hooks, c.urls[0], in, out)
	if err != nil {
		twerr, ok := err.(twirp.Error)
		if !ok {
			twerr = twirp.InternalErrorWith(err)
		}
		callClientError(ctx, c.opts.Hooks, twerr)
		return nil, err
	}

	callClientResponseReceived(ctx, c.opts.Hooks)

	return out, nil
}

// =========================
// SearchService JSON Client
// =========================

type searchServiceJSONClient struct {
	client      HTTPClient
	urls        [1]string
	interceptor twirp.Interceptor
	opts        twirp.ClientOptions
}

// NewSearchServiceJSONClient creates a JSON client that implements the SearchService interface.
// It communicates using JSON and can be configured with a custom HTTPClient.
func NewSearchServiceJSONClient(baseURL string, client HTTPClient, opts ...twirp.ClientOption) SearchService {
	if c, ok := client.(*http.Client); ok {
		client = withoutRedirects(c)
	}

	clientOpts := twirp.ClientOptions{}
	for _, o := range opts {
		o(&clientOpts)
	}

	// Using ReadOpt allows backwards and forwads compatibility with new options in the future
	literalURLs := false
	_ = clientOpts.ReadOpt("literalURLs", &literalURLs)
	var pathPrefix string
	if ok := clientOpts.ReadOpt("pathPrefix", &pathPrefix); !ok {
		pathPrefix = "/twirp" // default prefix
	}

	// Build method URLs: <baseURL>[<prefix>]/<package>.<Service>/<Method>
	serviceURL := sanitizeBaseURL(baseURL)
	serviceURL += baseServicePath(pathPrefix, "buf.alpha.registry.v1alpha1", "SearchService")
	urls := [1]string{
		serviceURL + "Search",
	}

	return &searchServiceJSONClient{
		client:      client,
		urls:        urls,
		interceptor: twirp.ChainInterceptors(clientOpts.Interceptors...),
		opts:        clientOpts,
	}
}

func (c *searchServiceJSONClient) Search(ctx context.Context, in *SearchRequest) (*SearchResponse, error) {
	ctx = ctxsetters.WithPackageName(ctx, "buf.alpha.registry.v1alpha1")
	ctx = ctxsetters.WithServiceName(ctx, "SearchService")
	ctx = ctxsetters.WithMethodName(ctx, "Search")
	caller := c.callSearch
	if c.interceptor != nil {
		caller = func(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
			resp, err := c.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*SearchRequest)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*SearchRequest) when calling interceptor")
					}
					return c.callSearch(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*SearchResponse)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*SearchResponse) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}
	return caller(ctx, in)
}

func (c *searchServiceJSONClient) callSearch(ctx context.Context, in *SearchRequest) (*SearchResponse, error) {
	out := new(SearchResponse)
	ctx, err := doJSONRequest(ctx, c.client, c.opts.Hooks, c.urls[0], in, out)
	if err != nil {
		twerr, ok := err.(twirp.Error)
		if !ok {
			twerr = twirp.InternalErrorWith(err)
		}
		callClientError(ctx, c.opts.Hooks, twerr)
		return nil, err
	}

	callClientResponseReceived(ctx, c.opts.Hooks)

	return out, nil
}

// ============================
// SearchService Server Handler
// ============================

type searchServiceServer struct {
	SearchService
	interceptor      twirp.Interceptor
	hooks            *twirp.ServerHooks
	pathPrefix       string // prefix for routing
	jsonSkipDefaults bool   // do not include unpopulated fields (default values) in the response
	jsonCamelCase    bool   // JSON fields are serialized as lowerCamelCase rather than keeping the original proto names
}

// NewSearchServiceServer builds a TwirpServer that can be used as an http.Handler to handle
// HTTP requests that are routed to the right method in the provided svc implementation.
// The opts are twirp.ServerOption modifiers, for example twirp.WithServerHooks(hooks).
func NewSearchServiceServer(svc SearchService, opts ...interface{}) TwirpServer {
	serverOpts := newServerOpts(opts)

	// Using ReadOpt allows backwards and forwads compatibility with new options in the future
	jsonSkipDefaults := false
	_ = serverOpts.ReadOpt("jsonSkipDefaults", &jsonSkipDefaults)
	jsonCamelCase := false
	_ = serverOpts.ReadOpt("jsonCamelCase", &jsonCamelCase)
	var pathPrefix string
	if ok := serverOpts.ReadOpt("pathPrefix", &pathPrefix); !ok {
		pathPrefix = "/twirp" // default prefix
	}

	return &searchServiceServer{
		SearchService:    svc,
		hooks:            serverOpts.Hooks,
		interceptor:      twirp.ChainInterceptors(serverOpts.Interceptors...),
		pathPrefix:       pathPrefix,
		jsonSkipDefaults: jsonSkipDefaults,
		jsonCamelCase:    jsonCamelCase,
	}
}

// writeError writes an HTTP response with a valid Twirp error format, and triggers hooks.
// If err is not a twirp.Error, it will get wrapped with twirp.InternalErrorWith(err)
func (s *searchServiceServer) writeError(ctx context.Context, resp http.ResponseWriter, err error) {
	writeError(ctx, resp, err, s.hooks)
}

// handleRequestBodyError is used to handle error when the twirp server cannot read request
func (s *searchServiceServer) handleRequestBodyError(ctx context.Context, resp http.ResponseWriter, msg string, err error) {
	if context.Canceled == ctx.Err() {
		s.writeError(ctx, resp, twirp.NewError(twirp.Canceled, "failed to read request: context canceled"))
		return
	}
	if context.DeadlineExceeded == ctx.Err() {
		s.writeError(ctx, resp, twirp.NewError(twirp.DeadlineExceeded, "failed to read request: deadline exceeded"))
		return
	}
	s.writeError(ctx, resp, twirp.WrapError(malformedRequestError(msg), err))
}

// SearchServicePathPrefix is a convenience constant that may identify URL paths.
// Should be used with caution, it only matches routes generated by Twirp Go clients,
// with the default "/twirp" prefix and default CamelCase service and method names.
// More info: https://twitchtv.github.io/twirp/docs/routing.html
const SearchServicePathPrefix = "/twirp/buf.alpha.registry.v1alpha1.SearchService/"

func (s *searchServiceServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	ctx = ctxsetters.WithPackageName(ctx, "buf.alpha.registry.v1alpha1")
	ctx = ctxsetters.WithServiceName(ctx, "SearchService")
	ctx = ctxsetters.WithResponseWriter(ctx, resp)

	var err error
	ctx, err = callRequestReceived(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	if req.Method != "POST" {
		msg := fmt.Sprintf("unsupported method %q (only POST is allowed)", req.Method)
		s.writeError(ctx, resp, badRouteError(msg, req.Method, req.URL.Path))
		return
	}

	// Verify path format: [<prefix>]/<package>.<Service>/<Method>
	prefix, pkgService, method := parseTwirpPath(req.URL.Path)
	if pkgService != "buf.alpha.registry.v1alpha1.SearchService" {
		msg := fmt.Sprintf("no handler for path %q", req.URL.Path)
		s.writeError(ctx, resp, badRouteError(msg, req.Method, req.URL.Path))
		return
	}
	if prefix != s.pathPrefix {
		msg := fmt.Sprintf("invalid path prefix %q, expected %q, on path %q", prefix, s.pathPrefix, req.URL.Path)
		s.writeError(ctx, resp, badRouteError(msg, req.Method, req.URL.Path))
		return
	}

	switch method {
	case "Search":
		s.serveSearch(ctx, resp, req)
		return
	default:
		msg := fmt.Sprintf("no handler for path %q", req.URL.Path)
		s.writeError(ctx, resp, badRouteError(msg, req.Method, req.URL.Path))
		return
	}
}

func (s *searchServiceServer) serveSearch(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	header := req.Header.Get("Content-Type")
	i := strings.Index(header, ";")
	if i == -1 {
		i = len(header)
	}
	switch strings.TrimSpace(strings.ToLower(header[:i])) {
	case "application/json":
		s.serveSearchJSON(ctx, resp, req)
	case "application/protobuf":
		s.serveSearchProtobuf(ctx, resp, req)
	default:
		msg := fmt.Sprintf("unexpected Content-Type: %q", req.Header.Get("Content-Type"))
		twerr := badRouteError(msg, req.Method, req.URL.Path)
		s.writeError(ctx, resp, twerr)
	}
}

func (s *searchServiceServer) serveSearchJSON(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	var err error
	ctx = ctxsetters.WithMethodName(ctx, "Search")
	ctx, err = callRequestRouted(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	d := json.NewDecoder(req.Body)
	rawReqBody := json.RawMessage{}
	if err := d.Decode(&rawReqBody); err != nil {
		s.handleRequestBodyError(ctx, resp, "the json request could not be decoded", err)
		return
	}
	reqContent := new(SearchRequest)
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err = unmarshaler.Unmarshal(rawReqBody, reqContent); err != nil {
		s.handleRequestBodyError(ctx, resp, "the json request could not be decoded", err)
		return
	}

	handler := s.SearchService.Search
	if s.interceptor != nil {
		handler = func(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
			resp, err := s.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*SearchRequest)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*SearchRequest) when calling interceptor")
					}
					return s.SearchService.Search(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*SearchResponse)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*SearchResponse) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}

	// Call service method
	var respContent *SearchResponse
	func() {
		defer ensurePanicResponses(ctx, resp, s.hooks)
		respContent, err = handler(ctx, reqContent)
	}()

	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}
	if respContent == nil {
		s.writeError(ctx, resp, twirp.InternalError("received a nil *SearchResponse and nil error while calling Search. nil responses are not supported"))
		return
	}

	ctx = callResponsePrepared(ctx, s.hooks)

	marshaler := &protojson.MarshalOptions{UseProtoNames: !s.jsonCamelCase, EmitUnpopulated: !s.jsonSkipDefaults}
	respBytes, err := marshaler.Marshal(respContent)
	if err != nil {
		s.writeError(ctx, resp, wrapInternal(err, "failed to marshal json response"))
		return
	}

	ctx = ctxsetters.WithStatusCode(ctx, http.StatusOK)
	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	resp.WriteHeader(http.StatusOK)

	if n, err := resp.Write(respBytes); err != nil {
		msg := fmt.Sprintf("failed to write response, %d of %d bytes written: %s", n, len(respBytes), err.Error())
		twerr := twirp.NewError(twirp.Unknown, msg)
		ctx = callError(ctx, s.hooks, twerr)
	}
	callResponseSent(ctx, s.hooks)
}

func (s *searchServiceServer) serveSearchProtobuf(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	var err error
	ctx = ctxsetters.WithMethodName(ctx, "Search")
	ctx, err = callRequestRouted(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	buf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		s.handleRequestBodyError(ctx, resp, "failed to read request body", err)
		return
	}
	reqContent := new(SearchRequest)
	if err = proto.Unmarshal(buf, reqContent); err != nil {
		s.writeError(ctx, resp, malformedRequestError("the protobuf request could not be decoded"))
		return
	}

	handler := s.SearchService.Search
	if s.interceptor != nil {
		handler = func(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
			resp, err := s.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*SearchRequest)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*SearchRequest) when calling interceptor")
					}
					return s.SearchService.Search(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*SearchResponse)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*SearchResponse) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}

	// Call service method
	var respContent *SearchResponse
	func() {
		defer ensurePanicResponses(ctx, resp, s.hooks)
		respContent, err = handler(ctx, reqContent)
	}()

	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}
	if respContent == nil {
		s.writeError(ctx, resp, twirp.InternalError("received a nil *SearchResponse and nil error while calling Search. nil responses are not supported"))
		return
	}

	ctx = callResponsePrepared(ctx, s.hooks)

	respBytes, err := proto.Marshal(respContent)
	if err != nil {
		s.writeError(ctx, resp, wrapInternal(err, "failed to marshal proto response"))
		return
	}

	ctx = ctxsetters.WithStatusCode(ctx, http.StatusOK)
	resp.Header().Set("Content-Type", "application/protobuf")
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	resp.WriteHeader(http.StatusOK)
	if n, err := resp.Write(respBytes); err != nil {
		msg := fmt.Sprintf("failed to write response, %d of %d bytes written: %s", n, len(respBytes), err.Error())
		twerr := twirp.NewError(twirp.Unknown, msg)
		ctx = callError(ctx, s.hooks, twerr)
	}
	callResponseSent(ctx, s.hooks)
}

func (s *searchServiceServer) ServiceDescriptor() ([]byte, int) {
	return twirpFileDescriptor17, 0
}

func (s *searchServiceServer) ProtocGenTwirpVersion() string {
	return "v8.1.0"
}

// PathPrefix returns the base service path, in the form: "/<prefix>/<package>.<Service>/"
// that is everything in a Twirp route except for the <Method>. This can be used for routing,
// for example to identify the requests that are targeted to this service in a mux.
func (s *searchServiceServer) PathPrefix() string {
	return baseServicePath(s.pathPrefix, "buf.alpha.registry.v1alpha1", "SearchService")
}

var twirpFileDescriptor17 = []byte{
	// 528 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x54, 0xc1, 0x6e, 0xd3, 0x40,
	0x10, 0x4d, 0x9c, 0x10, 0x35, 0x93, 0x26, 0x84, 0x15, 0x42, 0x56, 0x23, 0x44, 0xe5, 0x03, 0x0a,
	0x54, 0xd8, 0x6a, 0x2a, 0x4e, 0x48, 0x95, 0x1a, 0x2e, 0x39, 0x41, 0xb4, 0x69, 0x39, 0x94, 0x43,
	0xb4, 0x4e, 0x26, 0xce, 0x8a, 0xd8, 0x9b, 0xee, 0xae, 0x0b, 0xcd, 0x27, 0xf0, 0x19, 0x1c, 0x39,
	0xf0, 0x35, 0x7c, 0x10, 0xda, 0x75, 0x1d, 0xb9, 0x15, 0xb5, 0xd2, 0x9b, 0xe7, 0xcd, 0xcc, 0x9b,
	0xf7, 0x66, 0xbd, 0x0b, 0xfd, 0x30, 0x5d, 0x04, 0x6c, 0xb5, 0x5e, 0xb2, 0x40, 0x62, 0xc4, 0x95,
	0x96, 0x37, 0xc1, 0xf5, 0xb1, 0x05, 0x8e, 0x03, 0x85, 0x4c, 0xce, 0x96, 0xfe, 0x5a, 0x0a, 0x2d,
	0x48, 0x2f, 0x4c, 0x17, 0xbe, 0x4d, 0xf8, 0x79, 0xa5, 0x9f, 0x57, 0x7a, 0x14, 0x5e, 0x50, 0x5c,
	0x0b, 0xc5, 0xb5, 0x90, 0x37, 0x13, 0xdb, 0x46, 0x51, 0xa5, 0x2b, 0x4d, 0x3a, 0xe0, 0xf0, 0xb9,
	0x5b, 0x3d, 0xac, 0xf6, 0x9b, 0xd4, 0xe1, 0x73, 0x42, 0xa0, 0x9e, 0xb0, 0x18, 0x5d, 0xc7, 0x22,
	0xf6, 0x9b, 0x3c, 0x87, 0x27, 0xe2, 0x7b, 0x82, 0xd2, 0xad, 0x59, 0x30, 0x0b, 0xbc, 0x53, 0x70,
	0x3f, 0xcb, 0x88, 0x25, 0x7c, 0xc3, 0x34, 0x17, 0xc9, 0x63, 0x59, 0xbd, 0x53, 0xe8, 0x5e, 0x28,
	0x94, 0xa5, 0x7d, 0x07, 0xb0, 0x97, 0x2a, 0x94, 0x85, 0xde, 0x6d, 0xec, 0xcd, 0xa0, 0x7b, 0x8e,
	0x2c, 0x7e, 0xb4, 0x9b, 0x23, 0x78, 0x26, 0x0a, 0xba, 0xa7, 0xb6, 0x20, 0x73, 0xd6, 0x2d, 0x26,
	0x3e, 0x99, 0x21, 0x7f, 0x1d, 0xd8, 0xbf, 0x33, 0xe1, 0x02, 0x40, 0x6e, 0x37, 0x69, 0x27, 0xb5,
	0x06, 0x27, 0x7e, 0xc9, 0xee, 0xfd, 0xff, 0x2f, 0x7e, 0x54, 0xa1, 0x05, 0x22, 0xf2, 0x15, 0xf6,
	0x8b, 0xb3, 0xad, 0xe0, 0xd6, 0xe0, 0x7d, 0x29, 0xf1, 0x43, 0xdb, 0x1f, 0x55, 0xe8, 0x1d, 0x32,
	0xf2, 0x11, 0xea, 0x66, 0x6b, 0xd6, 0x64, 0x6b, 0xf0, 0xae, 0x94, 0xf4, 0xfe, 0x91, 0x8c, 0x2a,
	0xd4, 0x36, 0x1b, 0x12, 0x8d, 0x2c, 0x76, 0xeb, 0x3b, 0x90, 0xdc, 0x3f, 0x17, 0x43, 0x62, 0x9a,
	0x87, 0x0d, 0xa8, 0x73, 0x8d, 0xb1, 0xc7, 0xa0, 0x9d, 0xe7, 0xaf, 0x52, 0x54, 0xda, 0xfc, 0x62,
	0x57, 0x29, 0xde, 0x6e, 0xb4, 0x49, 0xb3, 0x80, 0xf4, 0xa0, 0xb9, 0x66, 0x11, 0x4e, 0x15, 0xdf,
	0x64, 0x67, 0xd8, 0xa6, 0x7b, 0x06, 0x98, 0xf0, 0x0d, 0x92, 0x97, 0x00, 0x36, 0xa9, 0xc5, 0x37,
	0x4c, 0xac, 0xb7, 0x36, 0xb5, 0xe5, 0xe7, 0x06, 0xf0, 0x7e, 0x56, 0xa1, 0xb3, 0xd5, 0xb0, 0x16,
	0x89, 0x42, 0x32, 0x86, 0x4e, 0x76, 0x65, 0xa6, 0xd2, 0xca, 0x52, 0x6e, 0xf5, 0xb0, 0xd6, 0x6f,
	0x0d, 0xde, 0x94, 0x9a, 0x29, 0x1a, 0xa1, 0x6d, 0x55, 0x88, 0x14, 0x79, 0x0d, 0x4f, 0x13, 0xfc,
	0xa1, 0xa7, 0x05, 0x21, 0x99, 0xcc, 0xb6, 0x81, 0xc7, 0xb9, 0x98, 0x81, 0xcc, 0xfd, 0x4e, 0x50,
	0x5e, 0xf3, 0x19, 0x12, 0x06, 0x8d, 0x0c, 0x20, 0x6f, 0x77, 0x1a, 0x6e, 0xb7, 0x74, 0x70, 0xb4,
	0x9b, 0x50, 0xeb, 0x76, 0xf8, 0xa7, 0x0a, 0xaf, 0x66, 0x22, 0x2e, 0x6b, 0x19, 0xb6, 0xb2, 0x9e,
	0xb1, 0x79, 0x41, 0x2e, 0x2f, 0x23, 0xae, 0x97, 0x69, 0xe8, 0xcf, 0x44, 0x1c, 0x84, 0xe9, 0x22,
	0x4c, 0xf9, 0x6a, 0x6e, 0x3e, 0x02, 0x9e, 0x68, 0x73, 0xe7, 0x56, 0x41, 0x84, 0x49, 0x60, 0x5f,
	0x9b, 0x20, 0x12, 0x41, 0xc9, 0xcb, 0xf4, 0x21, 0x47, 0x72, 0xe0, 0x97, 0x53, 0x1b, 0x9e, 0xd1,
	0xdf, 0x4e, 0x6f, 0x98, 0x2e, 0xfc, 0x33, 0x2b, 0x86, 0xe6, 0x62, 0xbe, 0xdc, 0xd6, 0x84, 0x0d,
	0x4b, 0x7d, 0xf2, 0x2f, 0x00, 0x00, 0xff, 0xff, 0x0f, 0x29, 0x83, 0xd4, 0xf4, 0x04, 0x00, 0x00,
}
