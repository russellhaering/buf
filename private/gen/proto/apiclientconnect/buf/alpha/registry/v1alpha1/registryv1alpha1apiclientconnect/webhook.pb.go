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

// Code generated by protoc-gen-go-apiclientconnect. DO NOT EDIT.

package registryv1alpha1apiclientconnect

import (
	context "context"

	registryv1alpha1connect "github.com/bufbuild/buf/private/gen/proto/connect/buf/alpha/registry/v1alpha1/registryv1alpha1connect"
	v1alpha1 "github.com/bufbuild/buf/private/gen/proto/go/buf/alpha/registry/v1alpha1"
	connect_go "github.com/bufbuild/connect-go"
	zap "go.uber.org/zap"
)

type webhookServiceClient struct {
	logger *zap.Logger
	client registryv1alpha1connect.WebhookServiceClient
}

// Create a webhook, subscribes to a given repository event for a callback URL invocation.
func (s *webhookServiceClient) CreateWebhook(
	ctx context.Context,
	webhookEvent v1alpha1.WebhookEvent,
	ownerName string,
	repositoryName string,
	callbackUrl string,
) (webhookSubscriptionId string, _ error) {
	response, err := s.client.CreateWebhook(
		ctx,
		connect_go.NewRequest(
			&v1alpha1.CreateWebhookRequest{
				WebhookEvent:   webhookEvent,
				OwnerName:      ownerName,
				RepositoryName: repositoryName,
				CallbackUrl:    callbackUrl,
			}),
	)
	if err != nil {
		return nil, err
	}
	return response.Msg.Webhook, nil
}

// Delete a webhook.
func (s *webhookServiceClient) DeleteWebhook(ctx context.Context, webhookSubscriptionId string) (_ error) {
	_, err := s.client.DeleteWebhook(
		ctx,
		connect_go.NewRequest(
			&v1alpha1.DeleteWebhookRequest{
				WebhookId: webhookId,
			}),
	)
	if err != nil {
		return err
	}
	return nil
}

// Lists the webhooks subscriptions for a given repository.
func (s *webhookServiceClient) ListWebhooks(
	ctx context.Context,
	repositoryName string,
	ownerName string,
	pageToken string,
) (webhooks []*v1alpha1.Webhook, nextPageToken string, _ error) {
	if s.contextModifier != nil {
		ctx = s.contextModifier(ctx)
	}
	response, err := s.client.ListWebhooks(
		ctx,
		connect_go.NewRequest(
			&v1alpha1.ListWebhooksRequest{
				RepositoryName: repositoryName,
				OwnerName:      ownerName,
				PageToken:      pageToken,
			}),
	)
	if err != nil {
		return nil, "", err
	}
	return response.Msg.Webhooks, response.Msg.NextPageToken, nil
}
