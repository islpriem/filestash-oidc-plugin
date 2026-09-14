package plg_authenticate_oidc

import (
	"slices"
	"strings"
)

// visibleFolders applies rules written one per line as "folder: group, group",
// where "*" stands for anyone signed in. Folders without a rule stay hidden.
func visibleFolders(rules string, groups []string) map[string]bool {
	folders := map[string]bool{}
	for _, line := range strings.Split(rules, "\n") {
		folder, allowed, ok := strings.Cut(line, ":")
		folder = strings.TrimSpace(folder)
		if !ok || folder == "" || strings.HasPrefix(folder, "#") {
			continue
		}
		for _, group := range strings.Split(allowed, ",") {
			group = strings.TrimSpace(group)
			if group == "*" || (group != "" && slices.Contains(groups, group)) {
				folders[folder] = true
			}
		}
	}
	return folders
}
