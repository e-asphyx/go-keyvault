package keyvault

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type TokenStorage interface {
	Get() Token
	Store(Token)
}

type Token interface {
	SetHeader(*http.Request)
	ExpiresAt() time.Time
	Token() string
	IsValid() bool
}

type defaultToken struct {
	token     string
	expiresAt time.Time
}

func (d *defaultToken) IsValid() bool {
	if d == nil {
		return false
	}
	return d.expiresAt.After(time.Now())
}

func (d *defaultToken) SetHeader(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+d.token)
}

func (d *defaultToken) Token() string {
	return d.token
}

func (d *defaultToken) ExpiresAt() time.Time {
	return d.expiresAt
}

type defaultTokenStorage struct {
	token Token
}

type noToken struct{}

func (n noToken) IsValid() bool               { return false }
func (n noToken) SetHeader(req *http.Request) {}
func (n noToken) Token() string               { return "" }
func (n noToken) ExpiresAt() time.Time        { return time.Unix(0, 0) }

func (d *defaultTokenStorage) Get() Token {
	if d.token == nil {
		return noToken{}
	}
	return d.token
}

func (d *defaultTokenStorage) Store(t Token) {
	d.token = t
}

type tokenResponse struct {
	ExpiresIn   json.Number `json:"expires_in"`
	AccessToken string      `json:"access_token"`
}

func newBearerToken(res *http.Response) (Token, error) {
	dec := json.NewDecoder(res.Body)
	var t tokenResponse
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}

	expiresIn, err := t.ExpiresIn.Int64()
	if err != nil {
		return nil, err
	}

	if expiresIn == 0 || t.AccessToken == "" {
		return nil, errors.New("Invalid token response")
	}

	return &defaultToken{
		token:     t.AccessToken,
		expiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
	}, nil
}
