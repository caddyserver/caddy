package dnsimple

import ()

// UsersService handles communication with the uer related
// methods of the DNSimple API.
//
// DNSimple API docs: http://developer.dnsimple.com/users/
type UsersService struct {
	client *Client
}

// User represents a DNSimple user.
type User struct {
	Id    int    `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
}

type userWrapper struct {
	User User `json:"user"`
}

// User gets the logged in user.
//
// DNSimple API docs: http://developer.dnsimple.com/users/
func (s *UsersService) User() (User, *Response, error) {
	wrappedUser := userWrapper{}

	res, err := s.client.get("user", &wrappedUser)
	if err != nil {
		return User{}, res, err
	}

	return wrappedUser.User, res, nil
}
