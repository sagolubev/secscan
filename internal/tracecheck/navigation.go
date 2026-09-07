// START_MODULE_CONTRACT
// PURPOSE: Validate source navigation metadata against Go declarations and repository files.
// SCOPE: Require changed-file maps and check marked legacy files without claiming semantic correctness.
// DEPENDS: internal/tracecheck/tracecheck.go, internal/tracecheck/git.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-source-navigation-comments, internal/tracecheck/navigation_test.go#TestNavigationRejectsInvalidMetadata
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// ValidateNavigation - Check source contracts, maps, marker pairs and local references.
// END_MODULE_MAP

package tracecheck

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"unicode"
)

// ValidateNavigation checks marked and changed Go files in cmd and internal.
// It validates structure and references, not behavioral claims or test sufficiency.
func ValidateNavigation(root string, changes []Change) error {
	tracked, err := gitOutput(root, "ls-files", "-z", "--", "cmd", "internal")
	if err != nil {
		return err
	}
	paths := make(map[string]bool)
	for _, path := range splitNull(tracked) {
		paths[path] = false
	}
	for _, change := range changes {
		paths[change.Path] = true
		if change.OldPath != "" {
			paths[change.OldPath] = true
		}
	}
	var names []string
	for path := range paths {
		if strings.HasSuffix(path, ".go") && (strings.HasPrefix(path, "cmd/") || strings.HasPrefix(path, "internal/")) {
			names = append(names, path)
		}
	}
	sort.Strings(names)
	var problems []error
	for _, path := range names {
		data, err := ReadRepositoryFile(root, path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("navigation %s: %w", path, err))
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, data, parser.ParseComments)
		if err != nil {
			problems = append(problems, fmt.Errorf("navigation %s: parse Go source: %w", path, err))
			continue
		}
		if err := validateNavigationFile(root, path, file, paths[path]); err != nil {
			problems = append(problems, fmt.Errorf("navigation %s: %w", path, err))
		}
	}
	return errors.Join(problems...)
}

func validateNavigationFile(root, path string, file *ast.File, required bool) error {
	symbols := navigationSymbols(file)
	fields := make(map[string]string)
	mapped := make(map[string]bool)
	seen := make(map[string]bool)
	var stack []string
	marked := false
	for _, group := range file.Comments {
		for _, comment := range group.List {
			body := strings.TrimPrefix(comment.Text, "//")
			if strings.HasPrefix(comment.Text, "/*") {
				body = strings.TrimSuffix(strings.TrimPrefix(comment.Text, "/*"), "*/")
			}
			for _, raw := range strings.Split(body, "\n") {
				line := strings.TrimSpace(raw)
				line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
				marker := navigationMarker(line)
				if marker {
					marked = true
					start := strings.HasPrefix(line, "START_")
					name := strings.TrimPrefix(strings.TrimPrefix(line, "START_"), "END_")
					valid := name == "MODULE_CONTRACT" || name == "MODULE_MAP"
					if strings.HasPrefix(name, "CONTRACT: ") {
						symbol := strings.TrimPrefix(name, "CONTRACT: ")
						valid = navigationFunction(file, symbol)
					}
					if strings.HasPrefix(name, "BLOCK_") {
						valid = token.IsIdentifier(strings.TrimPrefix(name, "BLOCK_"))
					}
					if !valid {
						return fmt.Errorf("invalid marker %q", line)
					}
					if strings.HasPrefix(name, "MODULE_") && comment.Pos() > file.Package {
						return fmt.Errorf("module metadata must precede package declaration")
					}
					if start {
						if seen[name] {
							return fmt.Errorf("duplicate marker %q", line)
						}
						if len(stack) > 0 && (!strings.HasPrefix(name, "BLOCK_") || !strings.HasPrefix(stack[len(stack)-1], "BLOCK_")) {
							return fmt.Errorf("invalid marker nesting at %q", line)
						}
						seen[name] = true
						stack = append(stack, name)
					} else {
						if len(stack) == 0 || stack[len(stack)-1] != name {
							return fmt.Errorf("unmatched marker %q", line)
						}
						stack = stack[:len(stack)-1]
					}
					continue
				}
				if len(stack) == 0 || line == "" {
					continue
				}
				switch stack[len(stack)-1] {
				case "MODULE_MAP":
					symbol, meaning, ok := strings.Cut(line, " - ")
					if !ok || !meaningfulNavigationText(meaning) {
						return fmt.Errorf("map entry requires symbol - meaning: %q", line)
					}
					if _, ok := symbols[symbol]; !ok {
						return fmt.Errorf("map symbol %q does not exist", symbol)
					}
					if mapped[symbol] {
						return fmt.Errorf("duplicate map symbol %q", symbol)
					}
					mapped[symbol] = true
				case "MODULE_CONTRACT":
					key, value, ok := strings.Cut(line, ":")
					_, duplicate := fields[key]
					if !ok || duplicate {
						return fmt.Errorf("invalid or duplicate contract field %q", line)
					}
					fields[key] = strings.TrimSpace(value)
				}
				if strings.HasPrefix(line, "LINKS:") {
					if err := validateNavigationReferences(root, strings.TrimSpace(strings.TrimPrefix(line, "LINKS:")), false); err != nil {
						return err
					}
				}
			}
		}
	}
	if len(stack) > 0 {
		return fmt.Errorf("unclosed marker %q", stack[len(stack)-1])
	}
	if !marked && !required {
		return nil
	}
	if !seen["MODULE_CONTRACT"] || !seen["MODULE_MAP"] {
		return fmt.Errorf("module contract and map are required")
	}
	for _, key := range []string{"PURPOSE", "SCOPE", "DEPENDS", "LINKS", "ROLE", "MAP_MODE"} {
		if fields[key] == "none" && key == "DEPENDS" {
			continue
		}
		if !meaningfulNavigationText(fields[key]) {
			return fmt.Errorf("module contract requires meaningful %s", key)
		}
	}
	role, mode := fields["ROLE"], fields["MAP_MODE"]
	if !(role == "RUNTIME" && mode == "EXPORTS" || (role == "SCRIPT" || role == "TEST") && mode == "LOCALS") {
		return fmt.Errorf("invalid ROLE/MAP_MODE pair %q/%q", role, mode)
	}
	if strings.HasSuffix(path, "_test.go") != (role == "TEST") {
		return fmt.Errorf("ROLE TEST must match the _test.go suffix")
	}
	if err := validateNavigationReferences(root, fields["DEPENDS"], true); err != nil {
		return err
	}
	if mode == "EXPORTS" {
		var missing []string
		for symbol, exported := range symbols {
			if exported && !mapped[symbol] {
				missing = append(missing, symbol)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return fmt.Errorf("map omits exports: %s", strings.Join(missing, ", "))
		}
	}
	return nil
}

func navigationMarker(line string) bool {
	for _, prefix := range []string{"START_MODULE_", "END_MODULE_", "START_CONTRACT", "END_CONTRACT", "START_BLOCK_", "END_BLOCK_"} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func meaningfulNavigationText(text string) bool {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "", "none", "todo", "tbd", "n/a":
		return false
	}
	return strings.ContainsFunc(text, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) })
}

// navigationSymbols records only declarations owned by this file, including methods.
func navigationSymbols(file *ast.File) map[string]bool {
	symbols := make(map[string]bool)
	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			name := declaration.Name.Name
			if declaration.Recv != nil {
				name = navigationReceiver(declaration.Recv.List[0].Type) + "." + name
			}
			symbols[name] = declaration.Name.IsExported()
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					symbols[spec.Name.Name] = spec.Name.IsExported()
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						if name.Name != "_" {
							symbols[name.Name] = name.IsExported()
						}
					}
				}
			}
		}
	}
	return symbols
}

func navigationReceiver(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.StarExpr:
		return navigationReceiver(expr.X)
	case *ast.IndexExpr:
		return navigationReceiver(expr.X)
	case *ast.IndexListExpr:
		return navigationReceiver(expr.X)
	}
	return ""
}

func navigationFunction(file *ast.File, name string) bool {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if function.Name.Name == name || function.Recv != nil && navigationReceiver(function.Recv.List[0].Type)+"."+function.Name.Name == name {
			return true
		}
	}
	return false
}

func validateNavigationReferences(root, value string, dependencies bool) error {
	if dependencies && value == "none" {
		return nil
	}
	for _, reference := range strings.Split(value, ",") {
		reference = strings.TrimSpace(reference)
		path, anchor, hasAnchor := strings.Cut(reference, "#")
		data, err := ReadRepositoryFile(root, path)
		if err != nil {
			return fmt.Errorf("reference %q: %w", reference, err)
		}
		if !hasAnchor {
			continue
		}
		if dependencies || anchor == "" {
			return fmt.Errorf("invalid reference anchor %q", reference)
		}
		switch {
		case strings.HasSuffix(path, ".go"):
			file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
			if err != nil {
				return fmt.Errorf("reference %q: %w", reference, err)
			}
			if _, ok := navigationSymbols(file)[anchor]; !ok {
				return fmt.Errorf("reference %q has no Go symbol", reference)
			}
		case strings.HasSuffix(path, ".md"):
			if !navigationHeading(data, anchor) {
				return fmt.Errorf("reference %q has no Markdown heading", reference)
			}
		default:
			return fmt.Errorf("unsupported reference anchor %q", reference)
		}
	}
	return nil
}

func navigationHeading(data []byte, anchor string) bool {
	seen := make(map[string]int)
	fence := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			if fence == "" {
				fence = line[:3]
			} else if strings.HasPrefix(line, fence) {
				fence = ""
			}
			continue
		}
		if fence != "" {
			continue
		}
		title := strings.TrimLeft(line, "#")
		level := len(line) - len(title)
		if level < 1 || level > 6 || !strings.HasPrefix(title, " ") {
			continue
		}
		title = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(title), "#"))
		slug := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return '-'
			}
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
				return unicode.ToLower(r)
			}
			return -1
		}, title)
		count := seen[slug]
		seen[slug]++
		if count > 0 {
			slug = fmt.Sprintf("%s-%d", slug, count)
		}
		if slug == anchor {
			return true
		}
	}
	return false
}
