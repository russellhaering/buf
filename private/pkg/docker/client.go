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

package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// TODO: Determine earliest version supporting required parameters
const currentVersion = "v1.41"

const headerXRegistryAuth = "X-Registry-Auth"

type HTTPError interface {
	StatusCode() int
}

type clientError struct {
	Code    int    `json:"-"`
	Message string `json:"message"`
}

func (c *clientError) Error() string {
	if len(c.Message) == 0 {
		return fmt.Sprintf("http status %d", c.Code)
	}
	return c.Message
}

func (c *clientError) StatusCode() int {
	return c.Code
}

type statusError struct {
	statusCode int
	wrapped    error
}

func (s *statusError) Error() string {
	return fmt.Sprintf("http status code: %d", s.statusCode)
}

func (s *statusError) StatusCode() int {
	return s.statusCode
}

func (s *statusError) Unwrap() error {
	return s.wrapped
}

type RegistryAuth struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Email         string `json:"email,omitempty"`
	ServerAddress string `json:"serveraddress,omitempty"` // domain/ip without a protocol
}

// ToHeader marshals the auth information as a base64 encoded JSON object.
// This is suitable for passing to the Docker API as the X-Registry-Auth header.
func (r *RegistryAuth) ToHeader() (string, error) {
	var buffer strings.Builder
	writer := base64.NewEncoder(base64.URLEncoding, &buffer)
	err := json.NewEncoder(writer).Encode(r)
	if err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

// FromHeader decodes auth information from a base64 encoded JSON object (see ToHeader).
func (r *RegistryAuth) FromHeader(encoded string) error {
	base64Reader := base64.NewDecoder(base64.URLEncoding, strings.NewReader(encoded))
	if err := json.NewDecoder(base64Reader).Decode(r); err != nil {
		return err
	}
	return nil
}

type ClientInterface interface {
	Image() ImageInterface
}

type ImageInterface interface {
	// Build creates an image using https://docs.docker.com/engine/api/v1.41/#operation/ImageBuild.
	Build(ctx context.Context, dockerContext io.Reader, params ImageBuildParams) (*ImageBuildResponse, error)
	// Inspect returns information about an image using https://docs.docker.com/engine/api/v1.41/#operation/ImageInspect.
	Inspect(ctx context.Context, imageName string, params ImageInspectParams) (*ImageInspectResponse, error)
	// Push publishes an image to a registry using https://docs.docker.com/engine/api/v1.41/#operation/ImagePush.
	Push(ctx context.Context, imageName string, params ImagePushParams) (*ImagePushResponse, error)
}

var _ ClientInterface = (*client)(nil)

type ClientOption func(*client)

// WithHTTPClient configures the underlying http.Client used for communicating with Docker.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

func WithLogger(logger *zap.Logger) ClientOption {
	return func(c *client) {
		c.logger = logger
	}
}

// NewClient creates a new Docker client with the specified options.
func NewClient(baseURL string, options ...ClientOption) (ClientInterface, error) {
	parsedURL, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return nil, err
	}
	client := &client{baseURL: parsedURL}
	for _, option := range options {
		option(client)
	}
	if client.httpClient == nil {
		client.httpClient = http.DefaultClient
	}
	if client.logger == nil {
		client.logger = zap.L()
	}
	return client, nil
}

type client struct {
	baseURL    *url.URL
	httpClient *http.Client
	logger     *zap.Logger
}

func (c *client) newRequest(ctx context.Context, method string, path string, body io.Reader) (*http.Request, error) {
	pathURL, err := c.baseURL.Parse("/" + currentVersion + "/" + path)
	if err != nil {
		return nil, err
	}
	return http.NewRequestWithContext(ctx, method, pathURL.String(), body)
}

func (c *client) Image() ImageInterface {
	return &imageClient{client: c}
}

type imageClient struct {
	client *client
}

var _ ImageInterface = (*imageClient)(nil)

func (i *imageClient) Build(ctx context.Context, dockerContext io.Reader, params ImageBuildParams) (*ImageBuildResponse, error) {
	query := make(url.Values)
	if len(params.Dockerfile) > 0 {
		query.Set("dockerfile", params.Dockerfile)
	}
	for _, tag := range params.Tags {
		query.Add("t", tag)
	}
	if params.Quiet {
		query.Set("quiet", "true")
	}
	if len(params.Args) > 0 {
		argsJSON, err := json.Marshal(params.Args)
		if err != nil {
			return nil, err
		}
		query.Set("buildargs", string(argsJSON))
	}
	if len(params.Labels) > 0 {
		labelsJSON, err := json.Marshal(params.Labels)
		if err != nil {
			return nil, err
		}
		query.Set("labels", string(labelsJSON))
	}
	if len(params.Platform) > 0 {
		query.Set("platform", params.Platform)
	}
	if len(params.Version) > 0 {
		query.Set("version", params.Version)
	}
	path := "build"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	req, err := i.client.newRequest(ctx, http.MethodPost, path, dockerContext)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-tar")

	response, err := i.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, parseError(response)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	i.client.logger.Info("succeeded", zap.String("op", "image/build"), zap.String("body", string(body)))
	// response body undocumented - if needed, provide a better interface to read it
	return &ImageBuildResponse{}, nil
}

func (i *imageClient) Inspect(ctx context.Context, imageName string, _ ImageInspectParams) (*ImageInspectResponse, error) {
	request, err := i.client.newRequest(ctx, http.MethodGet, "images/"+imageName+"/json", nil)
	if err != nil {
		return nil, err
	}
	response, err := i.client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, parseError(response)
	}
	var imageInfo ImageInspectResponse
	if err := json.NewDecoder(response.Body).Decode(&imageInfo); err != nil {
		return nil, err
	}
	i.client.logger.Info("succeeded", zap.String("op", "image/inspect"), zap.Any("response", imageInfo))
	return &imageInfo, nil
}

func (i *imageClient) Push(ctx context.Context, imageName string, params ImagePushParams) (*ImagePushResponse, error) {
	path := "images/" + imageName + "/push"
	query := make(url.Values)
	if len(params.Tag) > 0 {
		query.Set("tag", params.Tag)
	}
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	request, err := i.client.newRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}
	authHeader, err := params.Auth.ToHeader()
	if err != nil {
		return nil, err
	}
	request.Header.Set(headerXRegistryAuth, authHeader)
	response, err := i.client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, parseError(response)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	i.client.logger.Info("succeeded", zap.String("op", "image/push"), zap.String("body", string(body)))
	return &ImagePushResponse{}, nil
}

func parseError(response *http.Response) error {
	var clientErr clientError
	if err := json.NewDecoder(response.Body).Decode(&clientErr); err != nil {
		return &statusError{statusCode: response.StatusCode, wrapped: err}
	}
	clientErr.Code = response.StatusCode
	return &clientErr
}

type ImageBuildParams struct {
	Dockerfile string            // dockerfile: default: Dockerfile
	Tags       []string          // t: name:tag format
	Quiet      bool              // q:
	Args       map[string]string // buildargs:
	Labels     map[string]string // labels:
	Platform   string            // platform: os[/arch[/variant]]
	Version    string            // version: "1" for docker daemon, "2" for buildkit
}

type ImageBuildResponse struct {
}

type ImageInspectParams struct {
}

type ImageInspectResponse struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	// Any additional fields as needed: https://docs.docker.com/engine/api/v1.41/#operation/ImageInspect
}

type ImagePushParams struct {
	Auth *RegistryAuth
	Tag  string
}

type ImagePushResponse struct {
}
