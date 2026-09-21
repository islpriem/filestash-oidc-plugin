package plg_authenticate_oidc

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	. "github.com/mickael-kerjean/filestash/server/common"
)

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{
		"shared/readme.txt":  "shared",
		"team-1/readme.txt":  "team-1",
		"team-2/secret.txt":  "secret",
		"projects/plan.txt":  "plan",
		"hidden/private.txt": "private",
		"notes.txt":          "not a folder",
	} {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0755)
		os.WriteFile(p, []byte(content), 0644)
	}
	os.Mkdir(filepath.Join(root, "team-1", "sub"), 0755)
	os.Symlink("../team-2", filepath.Join(root, "team-1", "escape"))
	os.Symlink("/etc", filepath.Join(root, "team-1", "etc"))
	Config.Get("features.groupfolders.root").Set(root)
	Config.Get("features.groupfolders.rules").Set("shared: *\nteam-1: team-1\nteam-2: team-2\nprojects: team-1, team-2\nmissing: team-1")
	return root
}

func sealGrant(t *testing.T, groups []string, expiry time.Time) string {
	t.Helper()
	s, err := seal(grantPurpose, grant{Groups: groups, Expiry: expiry.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func connect(t *testing.T, groups ...string) IBackend {
	t.Helper()
	b, err := GroupFolders{}.Init(map[string]string{
		"type":     "groupfolders",
		"user":     "alice",
		"password": sealGrant(t, groups, time.Now().Add(time.Hour)),
	}, &App{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func names(t *testing.T, b IBackend, p string) []string {
	t.Helper()
	files, err := b.Ls(p)
	if err != nil {
		t.Fatalf("ls %s: %v", p, err)
	}
	out := []string{}
	for _, f := range files {
		out = append(out, f.Name())
	}
	slices.Sort(out)
	return out
}

func TestInitRequiresValidGrant(t *testing.T) {
	fixture(t)
	other, _ := seal("OTHER", grant{Groups: []string{"team-1"}, Expiry: time.Now().Add(time.Hour).Unix()})
	for name, password := range map[string]string{
		"missing":       "",
		"garbage":       "garbage",
		"other purpose": other,
		"expired":       sealGrant(t, []string{"team-1"}, time.Now().Add(-time.Second)),
	} {
		if _, err := (GroupFolders{}).Init(map[string]string{"password": password}, &App{}); err != ErrNotAuthorized {
			t.Errorf("%s: got %v, want %v", name, err, ErrNotAuthorized)
		}
	}
}

func TestInitRequiresAbsoluteRoot(t *testing.T) {
	fixture(t)
	Config.Get("features.groupfolders.root").Set("relative/path")
	_, err := GroupFolders{}.Init(map[string]string{"password": sealGrant(t, nil, time.Now().Add(time.Hour))}, &App{})
	if err == nil {
		t.Fatal("relative root accepted")
	}
}

func TestLsRootShowsVisibleFoldersOnly(t *testing.T) {
	fixture(t)
	for _, tc := range []struct {
		groups []string
		want   []string
	}{
		{[]string{"team-1"}, []string{"projects", "shared", "team-1"}},
		{[]string{"team-2"}, []string{"projects", "shared", "team-2"}},
		{nil, []string{"shared"}},
		{[]string{"..", "hidden", "TEAM-2", "team-1/../team-2"}, []string{"shared"}},
	} {
		if got := names(t, connect(t, tc.groups...), "/"); !slices.Equal(got, tc.want) {
			t.Errorf("groups %q: got %v, want %v", tc.groups, got, tc.want)
		}
	}
}

func TestWorkInsideFolder(t *testing.T) {
	fixture(t)
	b := connect(t, "team-1")

	if err := b.Save("/team-1/new.txt", strings.NewReader("hello")); err != nil {
		t.Fatal(err)
	}
	r, err := b.Cat("/team-1/new.txt")
	if err != nil {
		t.Fatal(err)
	}
	content, _ := io.ReadAll(r)
	r.Close()
	if string(content) != "hello" {
		t.Fatalf("cat: %q", content)
	}
	if info, err := b.Stat("/team-1/new.txt"); err != nil || info.Size() != 5 {
		t.Fatalf("stat: %v %v", info, err)
	}
	if err := b.Mkdir("/team-1/dir/"); err != nil {
		t.Fatal(err)
	}
	if err := b.Touch("/team-1/empty.txt"); err != nil {
		t.Fatal(err)
	}
	if err := b.Mv("/team-1/new.txt", "/team-1/dir/new.txt"); err != nil {
		t.Fatal(err)
	}
	if got := names(t, b, "/team-1/"); !slices.Equal(got, []string{"dir", "empty.txt", "readme.txt", "sub"}) {
		t.Fatalf("ls: %v", got)
	}
	if got := names(t, b, "/team-1/dir/"); !slices.Equal(got, []string{"new.txt"}) {
		t.Fatalf("ls dir: %v", got)
	}
	if err := b.Rm("/team-1/dir/"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Stat("/team-1/dir/"); err == nil {
		t.Fatal("rm left the directory behind")
	}
}

func TestForeignFoldersAreNotFound(t *testing.T) {
	root := fixture(t)
	b := connect(t, "team-1")
	for _, p := range []string{"/team-2/secret.txt", "/hidden/private.txt", "/team-1/../team-2/secret.txt", "/missing/x"} {
		checks := map[string]error{}
		_, checks["ls"] = b.Ls(filepath.Dir(p) + "/")
		_, checks["stat"] = b.Stat(p)
		_, checks["cat"] = b.Cat(p)
		checks["save"] = b.Save(p, strings.NewReader("x"))
		checks["touch"] = b.Touch(p + ".new")
		checks["mkdir"] = b.Mkdir(p + ".dir/")
		checks["rm"] = b.Rm(p)
		checks["mv from"] = b.Mv(p, "/team-1/stolen.txt")
		checks["mv to"] = b.Mv("/team-1/readme.txt", p)
		for op, err := range checks {
			if err != ErrNotFound {
				t.Errorf("%s %s: got %v, want %v", op, p, err, ErrNotFound)
			}
		}
	}
	if b, _ := os.ReadFile(filepath.Join(root, "team-2", "secret.txt")); string(b) != "secret" {
		t.Fatal("foreign file was modified")
	}
}

func TestSymlinksCannotLeaveFolder(t *testing.T) {
	root := fixture(t)
	b := connect(t, "team-1")
	if got := names(t, b, "/team-1/"); slices.Contains(got, "escape") || slices.Contains(got, "etc") {
		t.Fatalf("symlinks listed: %v", got)
	}
	if _, err := b.Ls("/team-1/escape/"); err == nil {
		t.Error("ls through symlink")
	}
	if _, err := b.Cat("/team-1/escape/secret.txt"); err == nil {
		t.Error("cat through symlink")
	}
	if _, err := b.Cat("/team-1/etc/passwd"); err == nil {
		t.Error("cat outside root through symlink")
	}
	if err := b.Save("/team-1/escape/planted.txt", strings.NewReader("x")); err == nil {
		t.Error("save through symlink")
	}
	if _, err := os.Stat(filepath.Join(root, "team-2", "planted.txt")); err == nil {
		t.Fatal("file planted in foreign folder")
	}
}

func TestRootAndFoldersThemselvesAreProtected(t *testing.T) {
	fixture(t)
	b := connect(t, "team-1", "team-2")
	for name, err := range map[string]error{
		"mkdir in root":      b.Mkdir("/new/"),
		"save in root":       b.Save("/file.txt", strings.NewReader("x")),
		"touch in root":      b.Touch("/file.txt"),
		"rm root":            b.Rm("/"),
		"rm folder":          b.Rm("/team-1/"),
		"mv folder":          b.Mv("/team-1/", "/team-1/moved/"),
		"mv onto folder":     b.Mv("/team-1/readme.txt", "/team-2"),
		"mv between folders": b.Mv("/team-1/readme.txt", "/team-2/readme.txt"),
		"save onto folder":   b.Save("/team-1", strings.NewReader("x")),
	} {
		if err == nil {
			t.Errorf("%s: allowed", name)
		}
	}
	if got := names(t, b, "/team-1/"); !slices.Contains(got, "readme.txt") {
		t.Fatalf("folder content changed: %v", got)
	}
}

func TestRulesApplyOnNextRequest(t *testing.T) {
	fixture(t)
	password := sealGrant(t, []string{"team-1"}, time.Now().Add(time.Hour))
	Config.Get("features.groupfolders.rules").Set("team-2: team-1")
	b, err := GroupFolders{}.Init(map[string]string{"password": password}, &App{})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(t, b, "/"); !slices.Equal(got, []string{"team-2"}) {
		t.Fatalf("got %v", got)
	}
}

func TestInterfaceOffersNoChangesToRoot(t *testing.T) {
	fixture(t)
	b := connect(t, "team-1").(interface{ Meta(string) Metadata })
	root := b.Meta("/")
	for name, allowed := range map[string]*bool{
		"create file":      root.CanCreateFile,
		"create directory": root.CanCreateDirectory,
		"upload":           root.CanUpload,
		"rename":           root.CanRename,
		"move":             root.CanMove,
		"delete":           root.CanDelete,
	} {
		if allowed == nil || *allowed {
			t.Errorf("%s offered in root", name)
		}
	}
	if inside := b.Meta("/team-1/"); inside != (Metadata{}) {
		t.Errorf("folder restricted: %+v", inside)
	}
}
