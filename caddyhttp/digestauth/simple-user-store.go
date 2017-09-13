package digestauth

import (
	"crypto/md5"
	"encoding/hex"
)

// A simpleUserStore uses a map to lookup strings of "user:realm" into "ha1"
type simpleUserStore struct {
	userToHA1 map[string]string
}

// Create a simple UserStore. You will pass in a map of the form { "username:realm": "md5(username:realm:password)", ... }
// It will be used to answer .Lookup() queries. The map is NOT copied. You could alter it if you wished to track new
// accounts or password changes, though I suggest you make your own implementation of UserStore instead of going that route.
// Spare your code readers.
func NewSimpleUserStore(users map[string]string) UserStore {
	us := simpleUserStore{userToHA1: users}
	return &us
}
func (us *simpleUserStore) Lookup(user string, realm string) (string, bool, error) {
	pass, ok := us.userToHA1[user]
	v := md5.Sum([]byte(user + ":" + realm + ":" + pass))
	hash := hex.EncodeToString(v[:])
	if ok {
		return hash, true, nil
	} else {
		return "", false, nil
	}
}
