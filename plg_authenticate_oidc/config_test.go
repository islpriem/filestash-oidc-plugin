package plg_authenticate_oidc

import (
	"maps"
	"slices"
	"testing"
)

const testRules = `
# folder: groups (comma separated), * = every signed-in user
shared: *
team-1: team-1
projects:  team-1 ,team-2
finance: accounting
Sales: Team-Sales
broken line
: team-1
empty:
trailing: team-3,
`

func TestVisibleFolders(t *testing.T) {
	for _, tc := range []struct {
		groups []string
		want   []string
	}{
		{[]string{"team-1"}, []string{"projects", "shared", "team-1"}},
		{[]string{"team-2"}, []string{"projects", "shared"}},
		{[]string{"team-1", "team-2"}, []string{"projects", "shared", "team-1"}},
		{[]string{"accounting"}, []string{"finance", "shared"}},
		{[]string{"Team-Sales"}, []string{"Sales", "shared"}},
		{[]string{"team-sales", "TEAM-1"}, []string{"shared"}},
		{[]string{"team-3"}, []string{"shared", "trailing"}},
		{[]string{"", "*", "broken line", "#"}, []string{"shared"}},
		{nil, []string{"shared"}},
	} {
		got := slices.Sorted(maps.Keys(visibleFolders(testRules, tc.groups)))
		if !slices.Equal(got, tc.want) {
			t.Errorf("groups %q: got %v, want %v", tc.groups, got, tc.want)
		}
	}
}

func TestVisibleFoldersWithoutRules(t *testing.T) {
	if got := visibleFolders("", []string{"team-1"}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}
