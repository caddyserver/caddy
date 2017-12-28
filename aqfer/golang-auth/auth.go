package auth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	"time"
)

const (
	accessTokenExpiry  = 7200            // 2 hours
	refreshTokenExpiry = 365 * 24 * 3600 // 1 year
	accessToken        = "access_token"
)

// To be initialized by go linker

var version string

// Service is the authentication service.
type Service struct {
	// SecurityContext has the details of the current user of the service.
	SecurityContext     *SecurityContext
	AccessKeySigningKey string
}

// AccessToken is the in-memory version of access token, which users of various web services will
// present as bearer tokens with their requests.
type AccessToken struct {
	Type        string `json:"type"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// RefreshToken is the in-memory version of access token, which users of web services will use to
// obtain access tokens.
type RefreshToken struct {
}

// SecurityContext holds the information about the current user.
type SecurityContext struct {
	User  string
	Email string
	Scope map[string]interface{}
	Type  string
	Roles []string
}

// UserInfo has the basic information about a user.
type UserInfo struct {
}

type VersionInfo struct {
	Version string `json:"version"`
}

type claims struct {
	jwt.StandardClaims
	User  string                 `json:"user"`
	Email string                 `json:"email"`
	Scope map[string]interface{} `json:"scope"`
	Type  string                 `json:"type"`
	Roles []string               `json:"role"`
}

// GetVersion returns the version of the service.
func (s *Service) GetVersion() (*VersionInfo, error) {
	return &VersionInfo{Version: version}, nil
}

// GetAccessToken generates and returns a new access token. This method is available for any authenticated user.
func (s *Service) GenerateAccessToken() (result *AccessToken, err error) {
	err = s.SecurityContext.authorizationCheck(nil, []string{"refresh_token"})
	if err != nil {
		return
	}
	now := time.Now().Unix()
	sc := s.SecurityContext
	claims := claims{
		StandardClaims: jwt.StandardClaims{
			Id:        uuid.NewV1().String(),
			IssuedAt:  now,
			ExpiresAt: now + accessTokenExpiry,
		},
		User:  sc.User,
		Email: sc.Email,
		Scope: sc.Scope,
		Type:  accessToken,
		Roles: sc.Roles,
	}
	tkn, err := mkJwtToken(s.AccessKeySigningKey, claims)
	if err == nil {
		result = &AccessToken{Type: "Bearer", AccessToken: tkn, ExpiresIn: accessTokenExpiry}
	}
	return
}

// ValidateToken validates a given bearer-token string and if valid returns the security context for that token
// This method is available only for those users who have permission to validate tokens.
func (s *Service) ValidateToken(token string) (result *SecurityContext, err error) {
	err = s.SecurityContext.authorizationCheck([]string{"access_key_validator"}, nil)
	if err == nil {
		parser := jwt.Parser{}
		claims := claims{}
		_, err = parser.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(s.AccessKeySigningKey), nil
		})
		if err == nil {
			err = claims.Valid()
			if err != nil {
				return
			}
			if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
				err = fmt.Errorf("token expired")
				return
			}
			result = &SecurityContext{
				User: claims.User, Email: claims.Email, Scope: claims.Scope, Type: claims.Type, Roles: claims.Roles,
			}
			return result, nil
		} else {
			err = fmt.Errorf("error validating token: %s", err)
			return nil, err
		}
	}
	return
}

// WhoAmI returns the details of the current user.
func (s *Service) WhoAmI() (*UserInfo, error) {
	return nil, fmt.Errorf("not implemented yet")
}

func (s *Service) GenerateRefreshToken(userInfo *UserInfo) (*RefreshToken, error) {
	return nil, fmt.Errorf("not implemented yet")
}

func (s *Service) RevokeRefreshToken(tokenId string) (*RefreshToken, error) {
	return nil, fmt.Errorf("not implemented yet")
}

func (s *Service) GetRefreshToken(tokenId string) (*RefreshToken, error) {
	return nil, fmt.Errorf("not implemented yet")
}

func (s *Service) ListRefreshTokens() ([]*RefreshToken, error) {
	return nil, fmt.Errorf("not implemented yet")
}

func mkJwtToken(key string, claims claims) (string, error) {
	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tkn.SignedString([]byte(key))
}

// in order to pass the check the current user must be in one of the roles and the security context must
// have type one of the expected types.
func (sc *SecurityContext) authorizationCheck(expectedRoles []string, expectedTypes []string) (err error) {
	if sc == nil {
		err = fmt.Errorf("not authenticated")
		return
	}
	found := false
	if expectedTypes == nil {
		found = true
	} else {
		for _, t := range expectedTypes {
			if t == sc.Type {
				found = true
				break
			}
		}
	}
	if found && expectedRoles != nil {
		found = false
		for _, r := range expectedRoles {
			if sc.userInRole(r) {
				found = true
				break
			}
		}
	}
	if !found {
		err = fmt.Errorf("not authorized")
	}
	return
}

func (sc *SecurityContext) userInRole(role string) bool {
	for _, s := range sc.Roles {
		if s == role {
			return true
		}
	}
	return false
}
