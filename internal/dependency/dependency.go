package dependency

import (
	"encoding/json"
	"io/ioutil"
	"path"

	"github.com/docker/cli/cli/command"

	"github.com/deislabs/cnab-go/bundle"
	"github.com/docker/app/types"
	"gopkg.in/yaml.v2"
)

type Dependencies struct {
	Dependencies []Dependency `yaml:"dependencies",json:"dependencies"`
}

type Dependency struct {
	Name        string            `yaml:"name",json:"name"`
	Image       string            `yaml:"image",json:"image"`
	Credentials map[string]string `yaml:"credentials",json:"credentials"`
	Parameters  map[string]string `yaml:"parameters",json:"parameters"`
	Context     *Context          `yaml:"context,omitempty",json:"context,omitempty"`
}

type Context struct {
	Name              string `yaml:"name",json:"name"`
	Description       string `yaml:"description",json:"description"`
	Orchestrator      string `yaml:"orchestrator",json:"orchestrator"`
	Kubeconfig        string `yaml:"kubeconfig",json:"kubeconfig"`
	Kubecontext       string `yaml:"kubecontext",json:"kubecontext"`
	FromDockerContext string `yaml:"from-docker-context",json:"from-docker-context"`
}

func AddDependencies(app *types.App, bndl *bundle.Bundle) error {
	for _, attachment := range app.Attachments() {
		if attachment.Path() == "dependencies.yml" {
			data, err := ioutil.ReadFile(path.Join(app.Path, attachment.Path()))
			if err != nil {
				return err
			}
			var deps Dependencies
			if err := yaml.Unmarshal(data, &deps); err != nil {
				return err
			}
			if err := validateDependencies(deps); err != nil {
				return err
			}
			bndl.Custom["com.docker.cnab.dependencies"] = deps
		}
	}

	return nil
}

func GetDependencies(bndl *bundle.Bundle) (*Dependencies, error) {
	raw, ok := bndl.Custom["com.docker.cnab.dependencies"]
	if !ok {
		return nil, nil
	}
	buf, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var deps Dependencies
	if err := json.Unmarshal(buf, &deps); err != nil {
		return nil, err
	}
	return &deps, nil
}

func validateDependencies(deps Dependencies) error {
	for _, dep := range deps.Dependencies {
		if dep.Context != nil {
			if _, err := command.NormalizeOrchestrator(dep.Context.Orchestrator); err != nil {
				return err
			}
		}
	}
	return nil
}
