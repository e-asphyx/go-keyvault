package keyvault

type Secret struct {
	keyVault    *KeyVault
	ID          string            `json:"id"`
	Attributes  *SecretAttributes `json:"attributes"`
	Tags        map[string]string `json:"tags"`
	ContentType string            `json:"contentType"`
	Managed     bool              `json:"managed"`
}

type SecretAttributes struct {
	Enabled       bool     `json:"enabled"`
	Created       UNIXTime `json:"created"`
	Updated       UNIXTime `json:"updated"`
	NotBefore     UNIXTime `json:"nbf"`
	Expires       UNIXTime `json:"exp"`
	RecoveryLevel string   `json:"recoverylevel"`
}

type SecretValue struct {
	Secret
	Value string `json:"value"`
	KID   string `json:"kid"`
}

func (s *Secret) Versions() ([]Secret, error) {
	return s.keyVault.secrets(s.ID + versionsPath)
}

func (s *Secret) Value() (*SecretValue, error) {
	var ret SecretValue
	if err := s.keyVault.Client.GetJSON(s.ID+"?"+apiVersionParam+"="+s.keyVault.apiVersion(), &ret); err != nil {
		return nil, err
	}
	ret.keyVault = s.keyVault

	return &ret, nil
}

type updateRequest struct {
	Value       string            `json:"value,omitempty"`
	Attributes  updateAttributes  `json:"attributes,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
}

type updateAttributes struct {
	NotBefore     *UNIXTime `json:"nbf,omitempty"`
	Expires       *UNIXTime `json:"exp,omitempty"`
	RecoveryLevel string    `json:"recoverylevel,omitempty"`
}

func (s *Secret) Set(value, contentType string, tags map[string]string, attributes *SecretAttributes) (*SecretValue, error) {
	req := updateRequest{
		Value:       value,
		ContentType: contentType,
		Tags:        tags,
	}
	if attributes != nil {
		if !attributes.Expires.IsZero() {
			req.Attributes.Expires = &attributes.Expires
		}

		if !attributes.NotBefore.IsZero() {
			req.Attributes.NotBefore = &attributes.NotBefore
		}

		req.Attributes.RecoveryLevel = attributes.RecoveryLevel
	}
	var ret SecretValue

	if err := s.keyVault.Client.PutJSON(s.ID+"?"+apiVersionParam+"="+s.keyVault.apiVersion(), &req, &ret); err != nil {
		return nil, err
	}
	ret.keyVault = s.keyVault

	return &ret, nil
}

func (s *Secret) Update(contentType string, tags map[string]string, attributes *SecretAttributes) (*SecretValue, error) {
	req := Secret{
		Attributes:  attributes,
		ContentType: contentType,
		Tags:        tags,
	}
	var ret SecretValue

	if err := s.keyVault.Client.PatchJSON(s.ID+"?"+apiVersionParam+"="+s.keyVault.apiVersion(), &req, &ret); err != nil {
		return nil, err
	}
	ret.keyVault = s.keyVault

	return &ret, nil
}
