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

package pluginpush

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/bufbuild/buf/private/buf/bufcli"
	"github.com/bufbuild/buf/private/bufpkg/bufanalysis"
	"github.com/bufbuild/buf/private/bufpkg/bufplugin/bufpluginconfig"
	"github.com/bufbuild/buf/private/bufpkg/bufplugin/bufpluginsource"
	"github.com/bufbuild/buf/private/pkg/app/appcmd"
	"github.com/bufbuild/buf/private/pkg/app/appflag"
	"github.com/bufbuild/buf/private/pkg/docker"
	"github.com/bufbuild/buf/private/pkg/stringutil"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

const (
	errorFormatFlagName     = "error-format"
	disableSymlinksFlagName = "disable-symlinks"
)

// NewCommand returns a new Command.
func NewCommand(
	name string,
	builder appflag.Builder,
) *appcmd.Command {
	flags := newFlags()
	return &appcmd.Command{
		Use:   name + " <source>",
		Short: "Push a plugin to a registry.",
		Long:  bufcli.GetSourceDirLong(`the source to push`),
		Args:  cobra.MaximumNArgs(1),
		Run: builder.NewRunFunc(
			func(ctx context.Context, container appflag.Container) error {
				return run(ctx, container, flags)
			},
			bufcli.NewErrorInterceptor(),
		),
		BindFlags: flags.Bind,
	}
}

type flags struct {
	ErrorFormat     string
	DisableSymlinks bool
}

func newFlags() *flags {
	return &flags{}
}

func (f *flags) Bind(flagSet *pflag.FlagSet) {
	bufcli.BindDisableSymlinks(flagSet, &f.DisableSymlinks, disableSymlinksFlagName)
	flagSet.StringVar(
		&f.ErrorFormat,
		errorFormatFlagName,
		"text",
		fmt.Sprintf(
			"The format for build errors printed to stderr. Must be one of %s.",
			stringutil.SliceToString(bufanalysis.AllFormatStrings),
		),
	)
}

func run(
	ctx context.Context,
	container appflag.Container,
	flags *flags,
) (retErr error) {
	if err := bufcli.ValidateErrorFormatFlag(flags.ErrorFormat, errorFormatFlagName); err != nil {
		return err
	}
	source, err := bufcli.GetInputValue(container, "" /* The input hashtag is not supported here */, ".")
	if err != nil {
		return err
	}
	storageosProvider := bufcli.NewStorageosProvider(flags.DisableSymlinks)
	sourceBucket, err := storageosProvider.NewReadWriteBucket(source)
	if err != nil {
		return err
	}
	existingConfigFilePath, err := bufpluginconfig.ExistingConfigFilePath(ctx, sourceBucket)
	if err != nil {
		return bufcli.NewInternalError(err)
	}
	if existingConfigFilePath == "" {
		return fmt.Errorf("please define a %s configuration file in the target directory", bufpluginconfig.ExternalConfigFilePath)
	}
	pluginConfig, err := bufpluginconfig.GetConfigForBucket(ctx, sourceBucket)
	if err != nil {
		return err
	}
	// TODO: Once we support multiple plugin source types, this could be abstracted away
	// in the bufpluginsource package. This is much simpler for now though.
	dockerfileInfo, err := sourceBucket.Get(ctx, bufpluginsource.DockerSourceFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("please define a %s plugin source file in the target directory", bufpluginsource.DockerSourceFilePath)
		}
		return err
	}
	defer dockerfileInfo.Close()

	dockerClient, err := docker.NewClient(
		// TODO: Currently unused
		"http://localhost",
		docker.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// TODO: We need to configure the path to Docker socket
					return net.Dial("unix", "/var/run/docker.sock")
				},
			},
		}),
		docker.WithLogger(container.Logger()),
	)
	if err != nil {
		return err
	}
	dockerContext, err := docker.CreateDockerContext(dockerfileInfo)
	if err != nil {
		return err
	}
	_, err = dockerClient.Image().Build(ctx, dockerContext, docker.ImageBuildParams{
		Tags:     []string{pluginConfig.Name.IdentityString()}, // TODO: Uses version latest for now,
		Platform: "linux/amd64",
		Version:  "2", // DOCKER_BUILDKIT=1
	})
	if err != nil {
		return err
	}

	imageInfo, err := dockerClient.Image().Inspect(ctx, pluginConfig.Name.IdentityString(), docker.ImageInspectParams{})
	if err != nil {
		return err
	}
	container.Logger().Info("created image",
		zap.String("id", imageInfo.ID),
		zap.Strings("tags", imageInfo.RepoTags),
		zap.Strings("digests", imageInfo.RepoDigests),
	)

	_, err = dockerClient.Image().Push(ctx, pluginConfig.Name.IdentityString(), docker.ImagePushParams{})
	if err != nil {
		return err
	}

	// TODO: Build and push the image to the OCI registry with the Docker library.
	// Once complete, use the digest in RPC below.
	//
	// We effectively need to codify the following:
	//
	//  $ docker build -f Dockerfile.twirp -t plugins.buf.build/demolab/twirp:v8.1.0-1 .
	//  $ docker push plugins.buf.build/demolab/twirp:v8.1.0-1
	//
	// This will look something along the lines of:
	//
	//  readObjectCloser, err := sourceBucket.Get(pluginSourceFilePath)
	//  if err != nil {
	//    return nil, err
	//  }
	//  defer func() {
	//    retErr = multierr.Append(retErr, readObjectCloser.Close())
	//  }()
	//  dockerfileContent, err := io.ReadAll(readObjectCloser)
	//  if err != nil {
	//    return nil, err
	//  }
	//  // Build and push to the OCI registry using the Docker library ...
	//
	// ---
	//
	// TODO: Now that the imageDigest is resolved, create a bufplugin.Plugin,
	// then map it into a *registryv1alpha1.RemotePlugin
	// (or *registryv1alpha1.CreateRemotePluginRequest) so that it can be pushed
	// to the BSR.
	//
	//  plugin, err := bufplugin.NewPlugin(
	//    pluginConfig.Options(),
	//    pluginConfig.Runtime(),
	//    imageDigest,
	//  )
	//  if err != nil {
	//    return err
	//  }
	//  protoPlugin, err := bufplugin.PluginToProtoPlugin(plugin)
	//  if err != nil {
	//    return err
	//  }
	//  // Use the RemotePluginService (shown below) ...
	//
	// ---
	//
	// TODO: At this point, it's possible that an OCI registry entry was created
	// without successfully creating the metadata in the BSR. If the user tries
	// to push again, the OCI registry entry might already exist. We need to explore
	// the OCI registry API to see what we can do to prevent such cases. This might
	// involve some combination of a cleanup process, a two-phase commit flow (i.e.
	// first create the metadata in the BSR, then push to the OCI registry, etc), or
	// something else entirely. This might not actually be an issue depending on the
	// OCI registry API.
	apiProvider, err := bufcli.NewRegistryProvider(ctx, container)
	if err != nil {
		return err
	}
	service, err := apiProvider.NewRemotePluginService(ctx, pluginConfig.Name.Remote())
	if err != nil {
		return err
	}
	if _, err := service.CreateRemotePlugin(
		ctx,
		pluginConfig.Name.Owner(),
		pluginConfig.Name.Plugin(),
		nil, // TODO: Add the protoPlugin.
	); err != nil {
		return err
	}
	// TODO: Print out the plugin that was just created.
	return nil
}
