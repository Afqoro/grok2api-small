package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// DecodeJWTClaims extracts claims from a JWT without validation.
// We only use this to read the expiry — the token itself is validated server-side by xAI.
func DecodeJWTClaims(token string) map[string]any {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// try standard encoding
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims
}

// TokenExpiry extracts the "exp" claim as a Unix timestamp. Returns 0 if absent or invalid.
func TokenExpiry(token string) int64 {
	claims := DecodeJWTClaims(token)
	if claims == nil {
		return 0
	}
	if exp, ok := claims["exp"]; ok {
		switch v := exp.(type) {
		case float64:
			return int64(v)
		case json.Number:
			n, _ := v.Int64()
			return n
		}
	}
	return 0
}

// IsTokenExpired returns true if the token expires within the given buffer duration.
// If expiry can't be determined (0), it returns false (assume valid, let upstream reject).
func IsTokenExpired(token string, buffer time.Duration) bool {
	exp := TokenExpiry(token)
	if exp == 0 {
		return false
	}
	return time.Now().Unix()+int64(buffer.Seconds()) >= exp
}

// ParseUserID extracts the "sub" claim.
func ParseUserID(token string) string {
	claims := DecodeJWTClaims(token)
	if claims == nil {
		return ""
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return ""
}

// ParseEmail extracts the "email" claim.
func ParseEmail(token string) string {
	claims := DecodeJWTClaims(token)
	if claims == nil {
		return ""
	}
	if email, ok := claims["email"].(string); ok {
		return email
	}
	return ""
}

// RefreshAndStore checks if the access token is expired, refreshes it via the refresh token,
// and updates the DB. Returns the fresh access token.
func RefreshAndStore(ctx context.Context, client *Client, db Database, cipher Cipher, accountID int64, encAccess, encRefresh string) (string, error) {
	accessToken, err := cipher.Decrypt(encAccess)
	if err != nil {
		return "", err
	}

	// Check expiry with 5 minute buffer
	if !IsTokenExpired(accessToken, 5*time.Minute) {
		return accessToken, nil
	}

	// Token expired or about to expire — refresh
	refreshToken, err := cipher.Decrypt(encRefresh)
	if err != nil {
		return "", err
	}

	tokens, err := client.RefreshToken(ctx, refreshToken)
	if err != nil {
		return "", err
	}

	// Encrypt new tokens
	newAccess, err := cipher.Encrypt(tokens.AccessToken)
	if err != nil {
		return "", err
	}
	newRefresh, err := cipher.Encrypt(tokens.RefreshToken)
	if err != nil {
		return "", err
	}

	exp := TokenExpiry(tokens.AccessToken)
	if err := db.UpdateAccountTokens(accountID, newAccess, newRefresh, exp); err != nil {
		return "", err
	}

	return tokens.AccessToken, nil
}

// Database interface to avoid circular import
type Database interface {
	UpdateAccountTokens(id int64, encAccess, encRefresh string, expiresAt int64) error
}

// Cipher interface to avoid circular import
type Cipher interface {
	Decrypt(s string) (string, error)
	Encrypt(s string) (string, error)
}
