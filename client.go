package keyvault

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const (
	oauthAPIVersion = "1.0"
	authHeader      = "WWW-Authenticate"
	tokenPath       = "/oauth2/token"
)

type Client struct {
	ClientID     string
	ClientSecret string
	Storage      TokenStorage
}

type KeyVaultError struct {
	Code       string         `json:"code"`
	Message    string         `json:"message`
	InnerError *KeyVaultError `json:"innererror`
}

func (k *KeyVaultError) Error() string {
	return "KeyVault: " + k.Code + ": " + k.Message
}

type authConfig struct {
	endpoint string
	resource string
}

func getAuthConfig(res *http.Response) (*authConfig, error) {
	authStr := res.Header.Get(authHeader)
	if authStr == "" {
		return nil, errors.New("Missing " + authHeader + " header in response")
	}

	s := strings.SplitN(authStr, " ", 2)
	if len(s) != 2 || s[0] != "Bearer" {
		return nil, errors.New("Authentication method must be Bearer")
	}

	var cfg authConfig
	for _, sub := range strings.Split(s[1], ",") {
		pair := strings.SplitN(strings.TrimSpace(sub), "=", 2)
		if len(pair) == 2 {
			key := pair[0]
			val := strings.Trim(pair[1], "\"")
			switch key {
			case "authorization":
				cfg.endpoint = val
			case "resource":
				cfg.resource = val
			}
		}
	}

	if cfg.endpoint == "" {
		return nil, errors.New("Empty endpoint URI")
	}

	if cfg.resource == "" {
		return nil, errors.New("Empty resource URI")
	}

	return &cfg, nil
}

func (c *Client) storage() TokenStorage {
	if c.Storage == nil {
		c.Storage = &defaultTokenStorage{}
	}
	return c.Storage
}

func (c *Client) authenticate(auth *authConfig) (Token, error) {
	q := url.Values{
		"grant_type":    []string{"client_credentials"},
		"client_id":     []string{c.ClientID},
		"resource":      []string{auth.resource},
		"client_secret": []string{c.ClientSecret},
	}

	body := bytes.NewReader([]byte(q.Encode()))
	req, err := http.NewRequest("POST", auth.endpoint+tokenPath+"?api-version="+oauthAPIVersion, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New(res.Status)
	}

	return newBearerToken(res)
}

func copyRequest(src *http.Request) *http.Request {
	dest := new(http.Request)
	*dest = *src
	dest.Header = make(http.Header)
	for k, v := range src.Header {
		dest.Header[k] = append([]string{}, v...)
	}
	return dest
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	attempt := 0
	for {
		r := req
		if tok := c.storage().Get(); tok != nil && tok.IsValid() {
			r = copyRequest(req)
			tok.SetHeader(r)
		}

		res, err := http.DefaultClient.Do(r)
		if err != nil {
			return nil, err
		}

		if res.StatusCode != http.StatusUnauthorized || attempt > 0 {
			return res, nil
		}

		ac, err := getAuthConfig(res)
		if err != nil {
			return nil, err
		}

		tok, err := c.authenticate(ac)
		if err != nil {
			return nil, err
		}
		c.storage().Store(tok)

		if req.GetBody != nil {
			req.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
		}

		attempt++
	}
}

func (c *Client) DoJSON(req *http.Request, dest interface{}) error {
	type errorResponse struct {
		Error KeyVaultError `json:"error"`
	}

	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	dec := json.NewDecoder(res.Body)

	if res.StatusCode != http.StatusOK {
		var errRes errorResponse
		if err := dec.Decode(&errRes); err != nil {
			return errors.New(res.Status)
		}
		return &errRes.Error
	}

	if err := dec.Decode(dest); err != nil {
		return err
	}

	return nil
}

func (c *Client) GetJSON(url string, dest interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "application/json")

	return c.DoJSON(req, dest)
}

func (c *Client) uploadJSON(method, url string, src, dest interface{}) error {
	buf, err := json.Marshal(src)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	return c.DoJSON(req, dest)
}

func (c *Client) PutJSON(url string, src, dest interface{}) error {
	return c.uploadJSON("PUT", url, src, dest)
}

func (c *Client) PatchJSON(url string, src, dest interface{}) error {
	return c.uploadJSON("PATCH", url, src, dest)
}
