package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"testing"
)

const filestash = "http://localhost:8334"

func TestVisibleFolders(t *testing.T) {
	for user, want := range map[string][]string{
		"alice":   {"projects", "shared", "team-1"},
		"bob":     {"projects", "shared", "team-2"},
		"carol":   {"finance", "shared"},
		"dave":    {"shared"},
		"mallory": {"shared"},
	} {
		t.Run(user, func(t *testing.T) {
			got, status := ls(t, signIn(t, user), "/")
			if status != http.StatusOK || !slices.Equal(got, want) {
				t.Fatalf("ls / = %v (%d), want %v", got, status, want)
			}
		})
	}
}

func TestWorkInsideFolder(t *testing.T) {
	c := signIn(t, "alice")
	if res, body := call(t, c, http.MethodGet, "/api/files/cat", url.Values{"path": {"/team-1/readme.txt"}}, nil); res.StatusCode != http.StatusOK || strings.TrimSpace(body) != "team-1" {
		t.Fatalf("cat: %d %q", res.StatusCode, body)
	}
	if res, body := call(t, c, http.MethodPost, "/api/files/cat", url.Values{"path": {"/projects/upload.txt"}}, strings.NewReader("hello")); res.StatusCode != http.StatusOK {
		t.Fatalf("upload: %d %s", res.StatusCode, body)
	}
	if res, body := call(t, c, http.MethodPost, "/api/files/mkdir", url.Values{"path": {"/projects/new/"}}, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("mkdir: %d %s", res.StatusCode, body)
	}
	if got, _ := ls(t, c, "/projects/"); !slices.Equal(got, []string{"new", "readme.txt", "upload.txt"}) {
		t.Fatalf("ls: %v", got)
	}
	if got, _ := ls(t, signIn(t, "bob"), "/projects/"); !slices.Contains(got, "upload.txt") {
		t.Fatalf("shared folder not shared: %v", got)
	}
}

func TestForeignAndEscapingPathsAreDenied(t *testing.T) {
	c := signIn(t, "alice")
	for _, tc := range []struct {
		method string
		path   string
		query  url.Values
	}{
		{http.MethodGet, "/api/files/ls", url.Values{"path": {"/team-2/"}}},
		{http.MethodGet, "/api/files/ls", url.Values{"path": {"/hidden/"}}},
		{http.MethodGet, "/api/files/ls", url.Values{"path": {"/team-1/../team-2/"}}},
		{http.MethodGet, "/api/files/ls", url.Values{"path": {"/team-1/escape/"}}},
		{http.MethodGet, "/api/files/cat", url.Values{"path": {"/team-2/readme.txt"}}},
		{http.MethodGet, "/api/files/cat", url.Values{"path": {"/team-1/escape/readme.txt"}}},
		{http.MethodGet, "/api/files/cat", url.Values{"path": {"/team-1/etc/passwd"}}},
		{http.MethodGet, "/api/files/cat", url.Values{"path": {"/notes.txt"}}},
		{http.MethodPost, "/api/files/cat", url.Values{"path": {"/team-2/planted.txt"}}},
		{http.MethodPost, "/api/files/mkdir", url.Values{"path": {"/new-folder/"}}},
		{http.MethodPost, "/api/files/rm", url.Values{"path": {"/team-1/"}}},
		{http.MethodPost, "/api/files/mv", url.Values{"from": {"/team-1/readme.txt"}, "to": {"/team-2/readme.txt"}}},
	} {
		if res, body := call(t, c, tc.method, tc.path, tc.query, strings.NewReader("x")); res.StatusCode == http.StatusOK {
			t.Errorf("%s %s %v: allowed: %s", tc.method, tc.path, tc.query, body)
		}
	}
	if got, _ := ls(t, signIn(t, "bob"), "/team-2/"); !slices.Equal(got, []string{"readme.txt"}) {
		t.Fatalf("team-2 changed: %v", got)
	}
}

func TestSignedOutRequestsAreRejected(t *testing.T) {
	if _, status := ls(t, newClient(t), "/"); status != http.StatusUnauthorized {
		t.Fatalf("status %d", status)
	}
}

func TestForgedSessionIsRejected(t *testing.T) {
	for _, password := range []string{"", "forged", "team-1,team-2"} {
		c := newClient(t)
		body := `{"type":"groupfolders","user":"mallory","password":"` + password + `"}`
		res, out := call(t, c, http.MethodPost, "/api/session", nil, strings.NewReader(body))
		if res.StatusCode == http.StatusOK || hasSession(c) {
			t.Errorf("password %q: session created: %s", password, out)
		}
	}
}

func TestCallbackIsBoundToTheBrowser(t *testing.T) {
	victim, attacker := newClient(t), newClient(t)
	callback := authorize(t, attacker, "mallory")
	get(t, victim, callback)
	if hasSession(victim) {
		t.Fatal("login forced onto another browser")
	}
	get(t, attacker, callback)
	if !hasSession(attacker) {
		t.Fatal("the browser that started the login could not finish it")
	}
}

func TestTamperedStateIsRejected(t *testing.T) {
	c := newClient(t)
	u, _ := url.Parse(authorize(t, c, "alice"))
	q := u.Query()
	q.Set("state", q.Get("state")+"x")
	u.RawQuery = q.Encode()
	get(t, c, u.String())
	if hasSession(c) {
		t.Fatal("tampered state accepted")
	}
}

func TestPostedCallbackIsRejected(t *testing.T) {
	c := newClient(t)
	u, _ := url.Parse(authorize(t, c, "alice"))
	res, err := c.PostForm(filestash+"/api/session/auth/", u.Query())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed || hasSession(c) {
		t.Fatalf("status %d", res.StatusCode)
	}
}

// The login page sends visitors straight to the provider when the only
// connection is the one behind the identity provider.
func TestLoginPageGoesStraightToProvider(t *testing.T) {
	var config struct {
		Result struct {
			Connections []map[string]any `json:"connections"`
			Auth        []string         `json:"auth"`
		} `json:"result"`
	}
	res, body := call(t, newClient(t), http.MethodGet, "/api/config", nil, nil)
	if err := json.Unmarshal([]byte(body), &config); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("config: %d %v", res.StatusCode, err)
	}
	if len(config.Result.Connections) != 1 || !slices.Equal(config.Result.Auth, []string{"Files"}) {
		t.Fatalf("connections=%v auth=%v", config.Result.Connections, config.Result.Auth)
	}
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

// authorize signs the user in at the mock provider the way a browser would
// and returns the callback the provider sends the browser to.
func authorize(t *testing.T, c *http.Client, user string) string {
	t.Helper()
	res := get(t, c, filestash+"/api/session/auth/?action=redirect&label=Files")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login page: status %d at %s", res.StatusCode, res.Request.URL)
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), filestash+"/api/session/auth/") {
			return http.ErrUseLastResponse
		}
		return nil
	}
	defer func() { c.CheckRedirect = nil }()
	res, err := c.PostForm(res.Request.URL.String(), url.Values{"username": {user}, "claims": {""}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	callback := res.Header.Get("Location")
	if !strings.HasPrefix(callback, filestash+"/api/session/auth/") {
		t.Fatalf("provider redirected to %q", callback)
	}
	return callback
}

func signIn(t *testing.T, user string) *http.Client {
	t.Helper()
	c := newClient(t)
	res := get(t, c, authorize(t, c, user))
	if !hasSession(c) {
		t.Fatalf("no session for %s, ended at %s", user, res.Request.URL)
	}
	return c
}

func hasSession(c *http.Client) bool {
	u, _ := url.Parse(filestash + "/api/")
	for _, cookie := range c.Jar.Cookies(u) {
		if cookie.Name == "auth" && cookie.Value != "" {
			return true
		}
	}
	return false
}

func get(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	res, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func call(t *testing.T, c *http.Client, method, path string, query url.Values, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, filestash+path+"?"+query.Encode(), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Requested-With", "XmlHttpRequest")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res, string(out)
}

func ls(t *testing.T, c *http.Client, path string) ([]string, int) {
	t.Helper()
	res, body := call(t, c, http.MethodGet, "/api/files/ls", url.Values{"path": {path}}, nil)
	var out struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}
	json.Unmarshal([]byte(body), &out)
	names := []string{}
	for _, r := range out.Results {
		names = append(names, r.Name)
	}
	slices.Sort(names)
	return names, res.StatusCode
}
