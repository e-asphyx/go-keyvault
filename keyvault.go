package keyvault

import (
	"encoding/json"
	"reflect"
	"strconv"
	"time"
)

const (
	secretsPath       = "/secrets"
	versionsPath      = "/versions"
	defaultAPIVersion = "2016-10-01"
	apiVersionParam   = "api-version"
)

type KeyVault struct {
	Client     *Client
	APIVersion string
	URL        string
}

func (k *KeyVault) getList(url string, tmpl interface{}) (interface{}, error) {
	type listReply struct {
		Value    json.RawMessage `json:"value"`
		NextLink string          `json:"nextLink"`
	}

	sliceType := reflect.SliceOf(reflect.TypeOf(tmpl))
	ret := reflect.MakeSlice(sliceType, 0, 25)

	url = url + "?" + apiVersionParam + "=" + k.apiVersion()
	for {
		var reply listReply
		if err := k.Client.GetJSON(url, &reply); err != nil {
			return nil, err
		}

		// MakeSlice returns unaddressable value
		val := reflect.New(sliceType)
		val.Elem().Set(reflect.MakeSlice(sliceType, 0, 25))
		if err := json.Unmarshal(reply.Value, val.Interface()); err != nil {
			return nil, err
		}
		ret = reflect.AppendSlice(ret, val.Elem())

		if reply.NextLink == "" {
			break
		}
		url = reply.NextLink
	}
	return ret.Interface(), nil
}

func (k *KeyVault) secrets(url string) ([]Secret, error) {
	ret, err := k.getList(url, Secret{})
	if err != nil {
		return nil, err
	}

	secrets := ret.([]Secret)
	for i := range secrets {
		secrets[i].keyVault = k
	}

	return secrets, nil
}

func (k *KeyVault) Secrets() ([]Secret, error) {
	return k.secrets(k.URL + secretsPath)
}

func (k *KeyVault) NewSecret(name string) *Secret {
	return &Secret{
		keyVault: k,
		ID:       k.URL + secretsPath + "/" + name,
	}
}

func (k *KeyVault) apiVersion() string {
	if k.APIVersion != "" {
		return k.APIVersion
	}
	return defaultAPIVersion
}

type UNIXTime struct {
	time.Time
}

func UNIXNow() UNIXTime {
	return UNIXTime{Time: time.Now()}
}

func (u UNIXTime) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(u.Unix(), 10)), nil
}

func (u *UNIXTime) UnmarshalJSON(data []byte) error {
	val, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	u.Time = time.Unix(val, 0)
	return nil
}
