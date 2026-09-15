package plg_authenticate_oidc

import (
	"slices"
	"strings"

	. "github.com/mickael-kerjean/filestash/server/common"
)

func folderRoot() string {
	return Config.Get("features.groupfolders.root").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Name = "root"
		f.Type = "text"
		f.Default = "/mnt/files"
		f.Placeholder = "Eg: /mnt/files"
		f.Description = "Directory holding the folders shared through the rules below"
		return f
	}).String()
}

func folderRules() string {
	return Config.Get("features.groupfolders.rules").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Name = "rules"
		f.Type = "long_text"
		f.Default = ""
		f.Placeholder = "shared: *\nteam-1: team-1\nprojects: team-1, team-2"
		f.Description = "One folder per line as 'folder: group, group'. Use * to share a folder with everyone signed in. Folders without a rule are hidden."
		return f
	}).String()
}

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
