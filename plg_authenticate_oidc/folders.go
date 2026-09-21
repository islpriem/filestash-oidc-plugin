package plg_authenticate_oidc

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	. "github.com/mickael-kerjean/filestash/server/common"
)

const (
	grantPurpose = "OIDC_GRANT"
	grantTTL     = 8 * time.Hour
)

// grant carries the groups of a user from the identity provider to the
// storage backend. It is sealed so it can't be forged through the regular
// login endpoint, and it expires so group changes eventually apply.
type grant struct {
	Groups []string `json:"groups"`
	Expiry int64    `json:"exp"`
}

type GroupFolders struct {
	root    string
	folders map[string]bool
}

func (this GroupFolders) Init(params map[string]string, app *App) (IBackend, error) {
	var g grant
	if err := unseal(grantPurpose, params["password"], &g); err != nil || time.Now().Unix() > g.Expiry {
		return nil, ErrNotAuthorized
	}
	root := folderRoot()
	if !filepath.IsAbs(root) {
		Log.Error("plg_authenticate_oidc::groupfolders root must be an absolute path")
		return nil, ErrNotValid
	}
	return &GroupFolders{
		root:    filepath.Clean(root),
		folders: visibleFolders(folderRules(), g.Groups),
	}, nil
}

func (this GroupFolders) LoginForm() Form {
	return Form{
		Elmnts: []FormElement{
			{
				Name:  "type",
				Type:  "hidden",
				Value: "groupfolders",
			},
			{
				Name:        "user",
				Type:        "text",
				Placeholder: "User",
			},
			{
				Name:        "password",
				Type:        "password",
				Placeholder: "Password",
			},
		},
	}
}

// Meta keeps the interface from offering changes to the root, which would be
// refused anyway.
func (this GroupFolders) Meta(p string) Metadata {
	if !isRoot(p) {
		return Metadata{}
	}
	return Metadata{
		CanCreateFile:      NewBool(false),
		CanCreateDirectory: NewBool(false),
		CanUpload:          NewBool(false),
		CanRename:          NewBool(false),
		CanMove:            NewBool(false),
		CanDelete:          NewBool(false),
	}
}

func (this GroupFolders) Ls(p string) ([]os.FileInfo, error) {
	files := []os.FileInfo{}
	if isRoot(p) {
		entries, err := os.ReadDir(this.root)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if info, err := entry.Info(); err == nil && entry.IsDir() && this.folders[entry.Name()] {
				files = append(files, info)
			}
		}
		return files, nil
	}
	root, rel, err := this.open(p)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && (entry.IsDir() || entry.Type().IsRegular()) {
			files = append(files, info)
		}
	}
	return files, nil
}

func (this GroupFolders) Stat(p string) (os.FileInfo, error) {
	if isRoot(p) {
		return os.Stat(this.root)
	}
	root, rel, err := this.open(p)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Stat(rel)
}

func (this GroupFolders) Cat(p string) (io.ReadCloser, error) {
	root, rel, err := this.open(p)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err != nil || info.IsDir() {
		f.Close()
		return nil, ErrNotFound
	}
	return f, nil
}

func (this GroupFolders) Mkdir(p string) error {
	root, rel, err := this.openInside(p)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Mkdir(rel, 0755)
}

func (this GroupFolders) Rm(p string) error {
	root, rel, err := this.openInside(p)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.RemoveAll(rel)
}

func (this GroupFolders) Mv(from string, to string) error {
	src, a, err := this.openInside(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, b, err := this.openInside(to)
	if err != nil {
		return err
	}
	defer dst.Close()
	if src.Name() != dst.Name() {
		return ErrNotAllowed
	}
	return src.Rename(a, b)
}

func (this GroupFolders) Save(p string, file io.Reader) error {
	root, rel, err := this.openInside(p)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
	if err != nil {
		return err
	}
	if _, err = io.Copy(f, file); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (this GroupFolders) Touch(p string) error {
	root, rel, err := this.openInside(p)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE, 0664)
	if err != nil {
		return err
	}
	return f.Close()
}

// open resolves p to one of the visible folders and the path relative to it.
// Everything below goes through os.Root so symlinks can't leave the folder.
func (this GroupFolders) open(p string) (*os.Root, string, error) {
	folder, rel, _ := strings.Cut(strings.TrimPrefix(path.Clean("/"+p), "/"), "/")
	if !this.folders[folder] {
		return nil, "", ErrNotFound
	}
	root, err := os.OpenRoot(filepath.Join(this.root, folder))
	if err != nil {
		return nil, "", ErrNotFound
	}
	if rel == "" {
		rel = "."
	}
	return root, rel, nil
}

// openInside is like open but refuses to touch the shared folder itself.
func (this GroupFolders) openInside(p string) (*os.Root, string, error) {
	root, rel, err := this.open(p)
	if err != nil {
		return nil, "", err
	} else if rel == "." {
		root.Close()
		return nil, "", ErrNotAllowed
	}
	return root, rel, nil
}

func isRoot(p string) bool {
	return path.Clean("/"+p) == "/"
}
