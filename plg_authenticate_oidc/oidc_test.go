package plg_authenticate_oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	. "github.com/mickael-kerjean/filestash/server/common"

	"github.com/go-jose/go-jose/v4"
)

const redirectURI = "http://files.example.com/api/session/auth/"

// idp is a minimal OpenID Connect provider issuing ID tokens for a single
// authorization code, bound to the PKCE challenge of the last login.
type idp struct {
	*httptest.Server
	key       *rsa.PrivateKey
	challenge string
	nonce     string
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &idp{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                i.URL,
			"authorization_endpoint":                i.URL + "/authorize",
			"token_endpoint":                        i.URL + "/token",
			"jwks_uri":                              i.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"},
		}})
	})
	i.Server = httptest.NewServer(mux)
	t.Cleanup(i.Close)
	return i
}

func (i *idp) params() map[string]string {
	return map[string]string{
		"issuer":        i.URL,
		"client_id":     "filestash",
		"client_secret": "secret",
		"redirect_uri":  redirectURI,
	}
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func entryPoint(t *testing.T, params map[string]string) (*url.URL, *http.Cookie) {
	t.Helper()
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/auth/?action=redirect&label=Files", nil)
	if err := (OpenID{}).EntryPoint(params, req, res); err != nil {
		t.Fatal(err)
	}
	if res.Code != http.StatusFound {
		t.Fatalf("status %d", res.Code)
	}
	location, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Result().Cookies() {
		if c.Name == flowCookie {
			return location, c
		}
	}
	t.Fatal("no flow cookie")
	return nil, nil
}

func TestSetup(t *testing.T) {
	fields := map[string]FormElement{}
	for _, el := range (OpenID{}).Setup().Elmnts {
		fields[el.Name] = el
	}
	if fields["type"].Type != "hidden" || fields["type"].Value != "oidc" {
		t.Fatalf("type: %+v", fields["type"])
	}
	for _, name := range []string{"issuer", "client_id", "client_secret", "redirect_uri"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("missing %s", name)
		}
	}
	if fields["client_secret"].Type != "password" {
		t.Errorf("client_secret is shown in clear")
	}
}

func TestEntryPointRedirectsToProvider(t *testing.T) {
	i := newIDP(t)
	location, cookie := entryPoint(t, i.params())

	if got := location.Scheme + "://" + location.Host + location.Path; got != i.URL+"/authorize" {
		t.Fatalf("redirected to %s", got)
	}
	q := location.Query()
	for name, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "filestash",
		"redirect_uri":          redirectURI,
		"scope":                 "openid profile email",
		"code_challenge_method": "S256",
	} {
		if q.Get(name) != want {
			t.Errorf("%s = %q, want %q", name, q.Get(name), want)
		}
	}
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if len(q.Get(name)) < 32 {
			t.Errorf("%s = %q is too weak", name, q.Get(name))
		}
	}

	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Secure {
		t.Errorf("cookie attributes: %+v", cookie)
	}
	if cookie.Path != WithBase("/api/session/auth/") || cookie.MaxAge <= 0 || cookie.MaxAge > 900 {
		t.Errorf("cookie scope: path=%s max-age=%d", cookie.Path, cookie.MaxAge)
	}
	for _, name := range []string{"state", "nonce"} {
		if strings.Contains(cookie.Value, q.Get(name)) {
			t.Errorf("cookie leaks %s", name)
		}
	}
	var f flow
	if err := unseal(flowPurpose, cookie.Value, &f); err != nil {
		t.Fatal(err)
	}
	if f.State != q.Get("state") || f.Nonce != q.Get("nonce") || s256(f.Verifier) != q.Get("code_challenge") {
		t.Fatal("cookie does not match the login")
	}
}

func TestEntryPointStartsFreshLogins(t *testing.T) {
	i := newIDP(t)
	a, _ := entryPoint(t, i.params())
	b, _ := entryPoint(t, i.params())
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if a.Query().Get(name) == b.Query().Get(name) {
			t.Errorf("%s reused", name)
		}
	}
}

func TestEntryPointSecureCookieOverHTTPS(t *testing.T) {
	i := newIDP(t)
	params := i.params()
	params["redirect_uri"] = "https://files.example.com/api/session/auth/"
	if _, cookie := entryPoint(t, params); !cookie.Secure {
		t.Fatal("cookie is not secure")
	}
}

func TestEntryPointUnreachableProvider(t *testing.T) {
	i := newIDP(t)
	params := i.params()
	i.Close()
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/auth/?action=redirect&label=Files", nil)
	if err := (OpenID{}).EntryPoint(params, req, res); err == nil {
		t.Fatal("no error")
	}
	if len(res.Result().Cookies()) != 0 || res.Header().Get("Location") != "" {
		t.Fatal("response was written")
	}
}

func TestBindFlow(t *testing.T) {
	Config.Get("middleware.identity_provider.type").Set("oidc")
	for _, tc := range []struct {
		name   string
		method string
		target string
		cookie string
		status int
		flow   string
	}{
		{"callback", http.MethodGet, "/api/session/auth/?code=c&state=s", "sealed", 0, "sealed"},
		{"callback without cookie", http.MethodGet, "/api/session/auth/?code=c&state=s&oidc_flow=forged", "", 0, ""},
		{"callback with forged flow", http.MethodGet, "/api/session/auth/?code=c&oidc_flow=forged&oidc_flow=again", "sealed", 0, "sealed"},
		{"posted callback", http.MethodPost, "/api/session/auth/?code=c&state=s", "sealed", http.StatusMethodNotAllowed, ""},
		{"posted redirect", http.MethodPost, "/api/session/auth/?action=redirect&code=c", "sealed", http.StatusMethodNotAllowed, ""},
		{"login start", http.MethodGet, "/api/session/auth/?action=redirect&label=Files", "sealed", 0, ""},
		{"other route", http.MethodPost, "/api/session?oidc_flow=x", "sealed", 0, "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called, seen := false, ""
			handler := bindFlow(func(ctx *App, res http.ResponseWriter, req *http.Request) {
				called, seen = true, req.URL.Query().Get(flowCookie)
			})
			req := httptest.NewRequest(tc.method, tc.target, nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: flowCookie, Value: tc.cookie})
			}
			res := httptest.NewRecorder()
			handler(&App{}, res, req)
			if tc.status != 0 {
				if called || res.Code != tc.status {
					t.Fatalf("called=%v status=%d, want %d", called, res.Code, tc.status)
				}
				return
			}
			if !called || seen != tc.flow {
				t.Fatalf("called=%v flow=%q, want %q", called, seen, tc.flow)
			}
		})
	}
}

func TestBindFlowOnlyForOIDC(t *testing.T) {
	Config.Get("middleware.identity_provider.type").Set("passthrough")
	defer Config.Get("middleware.identity_provider.type").Set("oidc")
	called := false
	handler := bindFlow(func(ctx *App, res http.ResponseWriter, req *http.Request) { called = true })
	handler(&App{}, httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/session/auth/", nil))
	if !called {
		t.Fatal("other authentication middlewares are blocked")
	}
}
