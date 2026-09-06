package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type Auth struct {
	Username    string
	Password    string
	TokenSecret string
	IsProduction bool
}

func New(username, password, tokenSecret string, isProduction bool) *Auth {
	return &Auth{
		Username:     username,
		Password:     password,
		TokenSecret:  tokenSecret,
		IsProduction: isProduction,
	}
}

func (a *Auth) VerifyCredentials(username, password string) bool {
	return subtleCompare(username, a.Username) && subtleCompare(password, a.Password)
}

func (a *Auth) CreateAuthToken() (string, error) {
	payload := map[string]interface{}{
		"username":  a.Username,
		"timestamp": time.Now().UnixMilli(),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	mac := hmac.New(sha256.New, []byte(a.TokenSecret))
	mac.Write([]byte(encodedPayload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return encodedPayload + "." + sig, nil
}

func (a *Auth) VerifyAuthToken(token string) bool {
	dotIndex := strings.LastIndex(token, ".")
	if dotIndex == -1 {
		return false
	}

	encodedPayload := token[:dotIndex]
	providedSig := token[dotIndex+1:]

	mac := hmac.New(sha256.New, []byte(a.TokenSecret))
	mac.Write([]byte(encodedPayload))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if len(providedSig) != len(expectedSig) {
		return false
	}
	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		return false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return false
	}

	var payload struct {
		Username  string `json:"username"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}

	tokenAge := time.Since(time.UnixMilli(payload.Timestamp))
	return tokenAge < 24*time.Hour && payload.Username == a.Username
}

func (a *Auth) IsAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("admin_token")
	if err != nil {
		return false
	}
	return a.VerifyAuthToken(cookie.Value)
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}
