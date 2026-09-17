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
	"slices"
	"strings"
	"testing"
	"time"

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
	claims    map[string]any
	signer    *rsa.PrivateKey
	unsigned  bool
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &idp{key: key, signer: key, claims: map[string]any{}}
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
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		user, password, _ := r.BasicAuth()
		r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if user != "filestash" || password != "secret" ||
			r.PostForm.Get("grant_type") != "authorization_code" ||
			r.PostForm.Get("code") != "valid-code" ||
			r.PostForm.Get("redirect_uri") != redirectURI ||
			s256(r.PostForm.Get("code_verifier")) != i.challenge {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access",
			"token_type":   "Bearer",
			"id_token":     i.idToken(t),
		})
	})
	i.Server = httptest.NewServer(mux)
	t.Cleanup(i.Close)
	return i
}

func (i *idp) idToken(t *testing.T) string {
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":                i.URL,
		"aud":                "filestash",
		"sub":                "8f1c2d",
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"groups":             []string{"team-1", "projects"},
		"nonce":              i.nonce,
		"iat":                now,
		"exp":                now + 300,
	}
	for k, v := range i.claims {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	payload, _ := json.Marshal(claims)
	if i.unsigned {
		enc := base64.RawURLEncoding
		return enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc.EncodeToString(payload) + "."
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: i.signer},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"),
	)
	if err != nil {
		t.Error(err)
		return ""
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Error(err)
		return ""
	}
	token, _ := jws.CompactSerialize()
	return token
}

// begin starts a login and returns what the browser brings back to the
// callback once the user is authenticated.
func (i *idp) begin(t *testing.T) map[string]string {
	t.Helper()
	location, cookie := entryPoint(t, i.params())
	i.challenge = location.Query().Get("code_challenge")
	i.nonce = location.Query().Get("nonce")
	return map[string]string{
		"code":     "valid-code",
		"state":    location.Query().Get("state"),
		"label":    "Files",
		flowCookie: cookie.Value,
	}
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

func TestCallback(t *testing.T) {
	i := newIDP(t)
	res := httptest.NewRecorder()
	attrs, err := (OpenID{}).Callback(i.begin(t), i.params(), res)
	if err != nil {
		t.Fatal(err)
	}
	if attrs["user"] != "alice" || attrs["email"] != "alice@example.com" || len(attrs) != 3 {
		t.Fatalf("attributes: %v", attrs)
	}
	var g grant
	if err := unseal(grantPurpose, attrs["password"], &g); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(g.Groups, []string{"team-1", "projects"}) {
		t.Fatalf("groups: %v", g.Groups)
	}
	if expiry := time.Unix(g.Expiry, 0); expiry.Before(time.Now().Add(grantTTL-time.Minute)) || expiry.After(time.Now().Add(grantTTL)) {
		t.Fatalf("expiry: %v", expiry)
	}
	cleared := false
	for _, c := range res.Result().Cookies() {
		cleared = cleared || (c.Name == flowCookie && c.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("flow cookie is not cleared")
	}
}

func TestCallbackFallsBackToSubject(t *testing.T) {
	i := newIDP(t)
	i.claims["preferred_username"] = nil
	attrs, err := (OpenID{}).Callback(i.begin(t), i.params(), httptest.NewRecorder())
	if err != nil || attrs["user"] != "8f1c2d" {
		t.Fatalf("user=%q err=%v", attrs["user"], err)
	}
}

func TestCallbackWithoutGroups(t *testing.T) {
	i := newIDP(t)
	i.claims["groups"] = nil
	attrs, err := (OpenID{}).Callback(i.begin(t), i.params(), httptest.NewRecorder())
	if err != nil {
		t.Fatal(err)
	}
	var g grant
	if err := unseal(grantPurpose, attrs["password"], &g); err != nil || len(g.Groups) != 0 {
		t.Fatalf("groups=%v err=%v", g.Groups, err)
	}
}

func TestCallbackRejects(t *testing.T) {
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, tamper := range map[string]func(t *testing.T, i *idp, form, params map[string]string){
		"provider error": func(t *testing.T, i *idp, form, params map[string]string) {
			form["error"] = "access_denied"
		},
		"missing flow": func(t *testing.T, i *idp, form, params map[string]string) {
			delete(form, flowCookie)
		},
		"tampered flow": func(t *testing.T, i *idp, form, params map[string]string) {
			c := byte('A')
			if form[flowCookie][10] == c {
				c = 'B'
			}
			form[flowCookie] = form[flowCookie][:10] + string(c) + form[flowCookie][11:]
		},
		"state of another login": func(t *testing.T, i *idp, form, params map[string]string) {
			challenge, nonce := i.challenge, i.nonce
			form["state"] = i.begin(t)["state"]
			i.challenge, i.nonce = challenge, nonce
		},
		"code of another login": func(t *testing.T, i *idp, form, params map[string]string) {
			i.begin(t)
		},
		"unknown code": func(t *testing.T, i *idp, form, params map[string]string) {
			form["code"] = "stolen-code"
		},
		"wrong client secret": func(t *testing.T, i *idp, form, params map[string]string) {
			params["client_secret"] = "wrong"
		},
		"foreign signature": func(t *testing.T, i *idp, form, params map[string]string) {
			i.signer = other
		},
		"unsigned token": func(t *testing.T, i *idp, form, params map[string]string) {
			i.unsigned = true
		},
		"wrong issuer": func(t *testing.T, i *idp, form, params map[string]string) {
			i.claims["iss"] = "https://evil.example.com"
		},
		"wrong audience": func(t *testing.T, i *idp, form, params map[string]string) {
			i.claims["aud"] = "another-client"
		},
		"expired token": func(t *testing.T, i *idp, form, params map[string]string) {
			i.claims["exp"] = time.Now().Add(-time.Minute).Unix()
		},
		"wrong nonce": func(t *testing.T, i *idp, form, params map[string]string) {
			i.claims["nonce"] = "replayed"
		},
		"missing nonce": func(t *testing.T, i *idp, form, params map[string]string) {
			i.claims["nonce"] = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			i := newIDP(t)
			form, params := i.begin(t), i.params()
			tamper(t, i, form, params)
			attrs, err := (OpenID{}).Callback(form, params, httptest.NewRecorder())
			if err == nil || attrs != nil {
				t.Fatalf("accepted: %v", attrs)
			}
			if err == ErrAuthenticationFailed {
				t.Fatal("would restart the login in a loop")
			}
		})
	}
}
