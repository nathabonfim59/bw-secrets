package cli

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		singleQuoted := len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\''
		value = stripOuterQuotes(value)
		if !singleQuoted {
			value = expandEnvVars(value, result)
		}

		result[key] = value
	}
	return result, scanner.Err()
}

func stripOuterQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

var varRe = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

func expandEnvVars(value string, fileVars map[string]string) string {
	return varRe.ReplaceAllStringFunc(value, func(match string) string {
		name := match
		if strings.HasPrefix(match, "${") {
			name = match[2 : len(match)-1]
		} else if strings.HasPrefix(match, "$") {
			name = match[1:]
		}
		if v, ok := fileVars[name]; ok {
			return v
		}
		return os.Getenv(name)
	})
}
