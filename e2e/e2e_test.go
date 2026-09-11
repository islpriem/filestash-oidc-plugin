package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
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

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

// signIn walks through the login flow of the mock provider the same way a
// browser would and returns a client holding the filestash session.
func signIn(t *testing.T, user string) *http.Client {
	t.Helper()
	c := newClient(t)
	res, err := c.Get(filestash + "/api/session/auth/?action=redirect&label=Files")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login page: status %d at %s", res.StatusCode, res.Request.URL)
	}
	res, err = c.PostForm(res.Request.URL.String(), url.Values{"username": {user}, "claims": {""}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
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

func api(t *testing.T, c *http.Client, method, path string, query url.Values) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, filestash+path+"?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Requested-With", "XmlHttpRequest")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body := map[string]any{}
	json.NewDecoder(res.Body).Decode(&body)
	return res, body
}

func ls(t *testing.T, c *http.Client, path string) ([]string, int) {
	t.Helper()
	res, body := api(t, c, http.MethodGet, "/api/files/ls", url.Values{"path": {path}})
	names := []string{}
	results, _ := body["results"].([]any)
	for _, r := range results {
		if entry, ok := r.(map[string]any); ok {
			names = append(names, entry["name"].(string))
		}
	}
	slices.Sort(names)
	return names, res.StatusCode
}
