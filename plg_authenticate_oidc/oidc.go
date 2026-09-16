package plg_authenticate_oidc

import (
	"context"
	"net/http"
	"strings"
	"time"

	. "github.com/mickael-kerjean/filestash/server/common"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	flowCookie  = "oidc_flow"
	flowPurpose = "OIDC_FLOW"
)

// flow is what has to survive the round trip to the identity provider. It
// lives in a sealed cookie scoped to the callback.
type flow struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

type OpenID struct{}

func (this OpenID) Setup() Form {
	return Form{
		Elmnts: []FormElement{
			{
				Name:  "type",
				Type:  "hidden",
				Value: "oidc",
			},
			{
				Name:        "issuer",
				Type:        "text",
				Placeholder: "Eg: https://auth.example.com/application/o/filestash/",
				Description: "Issuer of the OpenID Connect provider, as found in its discovery document",
			},
			{
				Name: "client_id",
				Type: "text",
			},
			{
				Name:        "client_secret",
				Type:        "password",
				Description: "Can be read from the environment with {{ .ENV_OIDC_CLIENT_SECRET }}",
			},
			{
				Name:        "redirect_uri",
				Type:        "text",
				Placeholder: "Eg: https://files.example.com/api/session/auth/",
				Description: "Must be registered with the provider. The groups claim of the ID token is used for the groupfolders storage",
			},
		},
	}
}

func (this OpenID) EntryPoint(idpParams map[string]string, req *http.Request, res http.ResponseWriter) error {
	ctx, cancel := context.WithTimeout(oidc.ClientContext(req.Context(), HTTPClient()), 10*time.Second)
	defer cancel()
	_, config, err := discover(ctx, idpParams)
	if err != nil {
		Log.Error("plg_authenticate_oidc::entrypoint discovery err=%s", err.Error())
		return ErrNotReachable
	}
	f := flow{
		State:    RandomString(32),
		Nonce:    RandomString(32),
		Verifier: oauth2.GenerateVerifier(),
	}
	value, err := seal(flowPurpose, f)
	if err != nil {
		return err
	}
	http.SetCookie(res, &http.Cookie{
		Name:     flowCookie,
		Value:    value,
		Path:     WithBase("/api/session/auth/"),
		MaxAge:   60 * 10,
		HttpOnly: true,
		Secure:   strings.HasPrefix(idpParams["redirect_uri"], "https://"),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(res, req, config.AuthCodeURL(
		f.State,
		oidc.Nonce(f.Nonce),
		oauth2.S256ChallengeOption(f.Verifier),
	), http.StatusFound)
	return nil
}

func (this OpenID) Callback(formData map[string]string, idpParams map[string]string, res http.ResponseWriter) (map[string]string, error) {
	return nil, ErrNotImplemented
}

func discover(ctx context.Context, idpParams map[string]string) (*oidc.Provider, *oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, idpParams["issuer"])
	if err != nil {
		return nil, nil, err
	}
	return provider, &oauth2.Config{
		ClientID:     idpParams["client_id"],
		ClientSecret: idpParams["client_secret"],
		RedirectURL:  idpParams["redirect_uri"],
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}, nil
}
