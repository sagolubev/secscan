package scanner

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// validatePoutineInput rejects missing format discriminators that the upstream
// parsers otherwise silently accept. It does not implement complete CI schemas.
func validatePoutineInput(target, path string) error {
	file, err := os.Open(filepath.Join(target, filepath.FromSlash(path)))
	if err != nil {
		return fmt.Errorf("cannot read staged CI input")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > 16<<20 {
		return fmt.Errorf("CI input exceeds 16 MiB limit")
	}
	decoder := yaml.NewDecoder(io.LimitReader(file, 16<<20))
	documents := 0
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
			return fmt.Errorf("invalid CI YAML document")
		}
		documents++
		if documents > 1 && path != ".gitlab-ci.yml" {
			return fmt.Errorf("multiple CI YAML documents unsupported by Poutine")
		}
		root := document.Content[0]
		fields := map[string]*yaml.Node{}
		for i := 0; i < len(root.Content); i += 2 {
			key := root.Content[i]
			if key.Kind != yaml.ScalarNode || fields[key.Value] != nil {
				return fmt.Errorf("invalid or duplicate CI root field")
			}
			fields[key.Value] = root.Content[i+1]
		}
		valid := false
		switch {
		case strings.HasPrefix(path, ".tekton/"):
			version, kind, spec := fields["apiVersion"], fields["kind"], fields["spec"]
			if version != nil && strings.HasPrefix(version.Value, "tekton.dev/") && kind != nil && kind.Value == "PipelineRun" && spec != nil && spec.Kind == yaml.MappingNode {
				for i := 0; i < len(spec.Content); i += 2 {
					if spec.Content[i].Value == "pipelineSpec" && spec.Content[i+1].Kind == yaml.MappingNode {
						valid = true
					}
				}
			}
		case path == ".gitlab-ci.yml":
			for key, value := range fields {
				switch key {
				case "spec", "include", "stages", "variables", "workflow", "default":
					valid = true
				}
				if value.Kind == yaml.MappingNode {
					for i := 0; i < len(value.Content); i += 2 {
						switch value.Content[i].Value {
						case "script", "trigger", "extends":
							valid = true
						}
					}
				}
			}
		case filepath.Dir(path) == ".github/workflows":
			valid = fields["on"] != nil && fields["jobs"] != nil && fields["jobs"].Kind == yaml.MappingNode
		case filepath.Base(path) == "action.yml" || filepath.Base(path) == "action.yaml":
			valid = fields["runs"] != nil && fields["runs"].Kind == yaml.MappingNode
		default:
			for _, key := range []string{"steps", "jobs", "stages", "extends"} {
				if field := fields[key]; field != nil && (field.Kind == yaml.SequenceNode || field.Kind == yaml.MappingNode) {
					valid = true
				}
			}
		}
		if !valid {
			return fmt.Errorf("missing or unsupported CI format discriminator")
		}
	}
	if documents == 0 {
		return fmt.Errorf("empty CI input")
	}
	return nil
}
