package entities

// TokenData is the information that the system stores.
type TokenData struct {
	Username       string
	TokenID        string
	RefreshToken   []byte
	ExpirationDate int64
}

// NewTokenData creates an instance of the structure
func NewTokenData(username string, tokenID string, refreshToken []byte,
	expirationDate int64) *TokenData {

	return &TokenData{Username: username,
		TokenID:        tokenID,
		RefreshToken:   refreshToken,
		ExpirationDate: expirationDate}
}
