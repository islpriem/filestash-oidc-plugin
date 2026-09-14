package plg_authenticate_oidc

import (
	"encoding/json"

	. "github.com/mickael-kerjean/filestash/server/common"
	"github.com/mickael-kerjean/filestash/server/pkg/env"
)

func seal(purpose string, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return EncryptString(secret(purpose), string(b))
}

func unseal(purpose string, s string, v any) error {
	str, err := DecryptString(secret(purpose), s)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(str), v)
}

// secret derives a key per purpose the same way filestash derives its own keys,
// so nothing sealed here can be confused with a session or with another purpose.
func secret(purpose string) string {
	return Hash(purpose+"_"+env.SECRET_KEY, len(env.SECRET_KEY))
}
