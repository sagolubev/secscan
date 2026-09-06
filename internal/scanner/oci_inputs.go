package scanner

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sagolubev/secscan/internal/report"
	"go.yaml.in/yaml/v3"
)

type imageReference struct {
	Reference string
	Locations []report.Location
}

var imageName = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$`)

func validImageReference(ref string) bool {
	if len(ref) > 512 {
		return false
	}
	name, digest, hasDigest := strings.Cut(ref, "@")
	if hasDigest && !ValidImageID(digest) {
		return false
	}
	return imageName.MatchString(name)
}

func parseOCIReferences(file string, data []byte) ([]imageReference, int, error) {
	var refs []imageReference
	unread := 0
	add := func(ref string, line int) {
		if validImageReference(ref) {
			refs = append(refs, imageReference{Reference: ref, Locations: []report.Location{{Path: file, Line: line}}})
		} else {
			unread++
		}
	}
	base := filepath.Base(file)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		stages := make(map[string]bool)
		lines := strings.Split(string(data), "\n")
		for i := 0; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			start := i + 1
			for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
				i++
				line = strings.TrimSuffix(line, "\\") + " " + strings.TrimSpace(lines[i])
			}
			fields := strings.Fields(line)
			if len(fields) == 0 || !strings.EqualFold(fields[0], "FROM") {
				continue
			}
			fields = fields[1:]
			if len(fields) > 0 && strings.HasPrefix(fields[0], "--platform=") {
				fields = fields[1:]
			}
			if len(fields) != 1 && !(len(fields) == 3 && strings.EqualFold(fields[1], "AS")) {
				unread++
				continue
			}
			ref := fields[0]
			if !strings.EqualFold(ref, "scratch") && !stages[strings.ToLower(ref)] {
				add(ref, start)
			}
			if len(fields) == 3 {
				stages[strings.ToLower(fields[2])] = true
			}
		}
		return refs, unread, nil
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	budget := 10000
	for documents := 0; ; documents++ {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil || documents >= 1000 {
			return nil, 0, fmt.Errorf("invalid or oversized image manifest")
		}
		if len(doc.Content) != 1 {
			continue
		}
		root, err := yamlFields(doc.Content[0], &budget, 0)
		if err != nil {
			return nil, 0, err
		}
		if root == nil {
			continue
		}
		if services := root["services"]; services != nil {
			entries, err := yamlFields(services, &budget, 0)
			if err != nil {
				return nil, 0, err
			}
			for _, service := range entries {
				fields, err := yamlFields(service, &budget, 0)
				if err != nil {
					return nil, 0, err
				}
				if image := fields["image"]; image != nil {
					node, err := yamlResolve(image, &budget, 0)
					if err != nil {
						return nil, 0, err
					}
					if node.Kind == yaml.ScalarNode {
						add(node.Value, image.Line)
					} else {
						unread++
					}
				}
			}
		}
		var visit func(map[string]*yaml.Node, int) error
		visit = func(fields map[string]*yaml.Node, depth int) error {
			if depth > 32 {
				return fmt.Errorf("image manifest nesting exceeds limit")
			}
			kind := fields["kind"]
			if kind == nil {
				return nil
			}
			if kind.Value == "List" {
				items, err := yamlResolve(fields["items"], &budget, 0)
				if err != nil {
					return err
				}
				if items == nil || items.Kind != yaml.SequenceNode {
					return nil
				}
				for _, item := range items.Content {
					child, err := yamlFields(item, &budget, 0)
					if err != nil {
						return err
					}
					if err := visit(child, depth+1); err != nil {
						return err
					}
				}
				return nil
			}
			var route []string
			switch kind.Value {
			case "Pod":
				route = []string{"spec"}
			case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job":
				route = []string{"spec", "template", "spec"}
			case "CronJob":
				route = []string{"spec", "jobTemplate", "spec", "template", "spec"}
			default:
				return nil
			}
			pod := fields
			for _, key := range route {
				var err error
				pod, err = yamlFields(pod[key], &budget, 0)
				if err != nil {
					return err
				}
				if pod == nil {
					return nil
				}
			}
			for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
				list, err := yamlResolve(pod[key], &budget, 0)
				if err != nil {
					return err
				}
				if list == nil {
					continue
				}
				if list.Kind != yaml.SequenceNode {
					unread++
					continue
				}
				for _, entry := range list.Content {
					fields, err := yamlFields(entry, &budget, 0)
					if err != nil {
						return err
					}
					image := fields["image"]
					if image == nil {
						unread++
						continue
					}
					node, err := yamlResolve(image, &budget, 0)
					if err != nil {
						return err
					}
					if node.Kind == yaml.ScalarNode {
						add(node.Value, image.Line)
					} else {
						unread++
					}
				}
			}
			return nil
		}
		if err := visit(root, 0); err != nil {
			return nil, 0, err
		}
	}
	return refs, unread, nil
}

func yamlResolve(node *yaml.Node, budget *int, depth int) (*yaml.Node, error) {
	if node == nil {
		return nil, nil
	}
	*budget--
	if *budget < 0 || depth > 64 {
		return nil, fmt.Errorf("YAML alias expansion exceeds limit")
	}
	if node.Kind == yaml.AliasNode {
		return yamlResolve(node.Alias, budget, depth+1)
	}
	return node, nil
}

func yamlFields(node *yaml.Node, budget *int, depth int) (map[string]*yaml.Node, error) {
	node, err := yamlResolve(node, budget, depth)
	if err != nil || node == nil {
		return nil, err
	}
	if depth > 64 {
		return nil, fmt.Errorf("YAML merge expansion exceeds limit")
	}
	if node.Kind != yaml.MappingNode {
		return nil, nil
	}
	fields := make(map[string]*yaml.Node)
	explicit := make(map[string]bool)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || explicit[key.Value] {
			return nil, fmt.Errorf("duplicate or invalid image manifest key")
		}
		explicit[key.Value] = true
		if key.Value == "<<" {
			merged, err := yamlResolve(value, budget, depth+1)
			if err != nil {
				return nil, err
			}
			list := []*yaml.Node{merged}
			if merged.Kind == yaml.SequenceNode {
				list = merged.Content
			}
			for _, part := range list {
				inherited, err := yamlFields(part, budget, depth+1)
				if err != nil {
					return nil, err
				}
				for k, v := range inherited {
					if fields[k] == nil {
						fields[k] = v
					}
				}
			}
		} else {
			fields[key.Value] = value
		}
	}
	return fields, nil
}
