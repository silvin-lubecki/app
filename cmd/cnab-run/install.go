package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/deislabs/cnab-go/bundle"
	"github.com/docker/app/internal"
	"github.com/docker/app/internal/packager"
	"github.com/docker/app/render"
	"github.com/docker/app/types"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/stack"
	"github.com/docker/cli/cli/command/stack/options"
	"github.com/docker/cli/cli/command/stack/swarm"
	composetypes "github.com/docker/cli/cli/compose/types"
	kubecontext "github.com/docker/cli/cli/context/kubernetes"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// imageMapFilePath is the path where the CNAB runtime will put the actual
	// service to image mapping to use
	imageMapFilePath = "/cnab/app/image-map.json"
)

func installAction(instanceName string) error {
	cli, err := setupDockerContext()
	if err != nil {
		return errors.Wrap(err, "unable to restore docker context")
	}
	app, err := packager.Extract("")
	// todo: merge additional compose file
	if err != nil {
		return err
	}
	defer app.Cleanup()

	orchestratorRaw := os.Getenv(internal.DockerStackOrchestratorEnvVar)
	orchestrator, err := cli.StackOrchestrator(orchestratorRaw)
	if err != nil {
		return err
	}
	imageMap, err := getBundleImageMap()
	if err != nil {
		return err
	}
	parameters := packager.ExtractCNABParametersValues(packager.ExtractCNABParameterMapping(app.Parameters()), os.Environ())
	if orchestrator == command.OrchestratorKubernetes {
		if err := applyPlainKubernetes(cli, app, parameters); err != nil {
			return err
		}
	}
	rendered, err := render.Render(app, parameters, imageMap)
	if err != nil {
		return err
	}
	if err = addLabels(rendered); err != nil {
		return err
	}
	addAppLabels(rendered, instanceName)

	if err := os.Chdir(app.Path); err != nil {
		return err
	}
	sendRegistryAuth, err := strconv.ParseBool(os.Getenv("DOCKER_SHARE_REGISTRY_CREDS"))
	if err != nil {
		return err
	}
	// todo: pass registry auth to invocation image
	return stack.RunDeploy(cli, getFlagset(orchestrator), rendered, orchestrator, options.Deploy{
		Namespace:        instanceName,
		ResolveImage:     swarm.ResolveImageAlways,
		SendRegistryAuth: sendRegistryAuth,
	})
}

func applyPlainKubernetes(cli command.Cli, app *types.App, parameters map[string]string) error {
	// Parse attachments to find kube-manifest.yml file
	for _, a := range app.Attachments() {
		if strings.HasSuffix(a.Path(), "kube-manifest.yml") {
			buf, err := ioutil.ReadFile(filepath.Join(app.Path, a.Path()))
			if err != nil {
				return err
			}
			// Read Manifest
			manifest := []string{}
			if err := yaml.Unmarshal(buf, &manifest); err != nil {
				return err
			}
			// Retrieve kube context from cli context store
			kubeConfig, err := kubecontext.ConfigFromContext("cnab", cli.ContextStore())
			if err != nil {
				return err
			}
			rawCfg, err := kubeConfig.RawConfig()
			if err != nil {
				return err
			}
			data, err := clientcmd.Write(rawCfg)
			if err != nil {
				return err
			}
			tmp, err := ioutil.TempDir("", "")
			if err != nil {
				return err
			}
			configPath := filepath.Join(tmp, "config")
			if err := ioutil.WriteFile(configPath, data, 0644); err != nil {
				return err
			}

			// Apply all the k8s yaml files
			for _, m := range manifest {
				fmt.Printf("Applying Kube YAML file %q\n", m)
				kubeYaml, err := ioutil.ReadFile(filepath.Join(app.Path, m))
				if err != nil {
					return err
				}
				kubeYamlRendered, err := render.RenderFile(app, parameters, string(kubeYaml))
				if err != nil {
					return err
				}

				kubectlCmd := exec.Command("kubectl", "apply", "-f", "-")
				kubectlCmd.Stdin = bytes.NewBuffer([]byte(kubeYamlRendered))
				kubectlCmd.Stdout = os.Stdout
				kubectlCmd.Stderr = os.Stderr
				kubectlCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", configPath))
				if err := kubectlCmd.Run(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func getFlagset(orchestrator command.Orchestrator) *pflag.FlagSet {
	result := pflag.NewFlagSet("", pflag.ContinueOnError)
	if orchestrator == command.OrchestratorKubernetes {
		result.String("namespace", os.Getenv(internal.DockerKubernetesNamespaceEnvVar), "")
	}
	return result
}

func getBundleImageMap() (map[string]bundle.Image, error) {
	mapJSON, err := ioutil.ReadFile(imageMapFilePath)
	if err != nil {
		return nil, err
	}
	var result map[string]bundle.Image
	if err := json.Unmarshal(mapJSON, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func addLabels(rendered *composetypes.Config) error {
	args, err := ioutil.ReadFile(internal.DockerArgsPath)
	if err != nil {
		return err
	}
	var a packager.DockerAppArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return err
	}
	for k, v := range a.Labels {
		for i, service := range rendered.Services {
			if service.Labels == nil {
				service.Labels = map[string]string{}
			}
			service.Labels[k] = v
			rendered.Services[i] = service
		}
	}
	return nil
}

func addAppLabels(rendered *composetypes.Config, instanceName string) {
	for i, service := range rendered.Services {
		if service.Labels == nil {
			service.Labels = map[string]string{}
		}
		service.Labels[internal.LabelAppNamespace] = instanceName
		service.Labels[internal.LabelAppVersion] = internal.Version
		rendered.Services[i] = service
	}
}
