/*
Package digest provides HTTP Digest authentication.

You may use Apache style htdigest files,
a simple map of userXrealm->MD5(user:realm:password) or your own implementation of a user
lookup function (if perhaps you use a database).

The API is designed for HTTP request routers like Martini. It provides a handler, which
will do nothing to the HTTP response for valid authentication. For invalid authentication
it will make an http.Error(), which will usually be a 401 (Unauthorized) to request
authentication from a user.

You might use digest like this if you were getting passwords from your own source:

     m := martini.Classic()
     ...
     myUserStore := auth.NewSimpleUserStore(  map[string]string{
			"foo:mortal": "3791e8e14a10b3666ba15d9e78e4b359",    // pw is 'bar'
			"Mufasa:testrealm@host.com": "939e7578ed9e3c518a452acee763bce9",   // pw is 'Circle Of Life'
                    })
     ...
     digester := auth.NewDigestHandler( "mortal", nil, nil, myUserStore )
     m.Use( digester.ServeHTTP )   // this will force authentication of all requests, you can be more specific.

If you want to use htdigest files (because I know you thought about passing credentials on the command line
or in environment variables and you should know better):

     m := martini.Classic()
     ...
     // Read file: hint, the nil is standing in for a malformed line reporter function.
     myUserFile,err := auth.NewHtdigestUserStore("path/to/my/htdigest/file", nil)
     if err != nil {
		log.Fatalf("Unable to load password file '%s': %s", digestfile, err.Error())
     }
     ...
     digester := auth.NewDigestHandler( "My Realm", nil, nil, myUserFile )
     ...
     m.Post("/my-sensitive-uri", digester.ServeHTTP, mySensitiveHandler)  // just protect this one, notice chained handlers.

You will have noticed that both New*Handler calls included a pair of
nils. If you don't like the way nonces are created, tracked, and expired,
then you will want to replace one or both of these with your own
implementations of Nonce and NonceStore.  Otherwise, ignore those
interfaces.  The default is a 64 bit random nonce which will last for
about 100 uses before going stale. The NonceStore expires nonces which
are unused for about 5 to 10 minutes.
*/
package digestauth

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

var _ = log.Printf

// A BadLineHandler is used to notice bad lines in an htdigest file. If not nil, it will be
// called for each bad line with a descriptive error. Think about what you do with these, they
// will sometimes contain hashed passwords.
type BadLineHandler func(err error)

type UserStore interface {
	// Look up a user in a realm. Valid is xxx,true,nil
	// bool false means no such user.
	// error not nil means something when wrong in the store
	Lookup(user string, realm string) (string, bool, error)
}

// Each nonce created is tracked with a Nonce. The default lasts about
// 100 'nc' uses before going stale.
type Nonce interface {
	// Return the nonce string to be passed to the client
	Value() string

	// This is used when a nonce is expiring to get a new one in order
	// to chain in a sane manner.
	Next() Nonce

	// Returns true iff the nonce should be marked as stale to force a replacement,
	// ideally without ever rejecting a request.
	Stale() bool

	// Check is a particular 'nc' is acceptable at this time, and consume it if it
	// is. The function is not idempotent!
	AcceptCounter(uint) bool

	// Mark this Nonce as worn out. It should get a Next() in place and
	// after an interval, identify itself as Stale() in future calls.
	// The interval is to allow any inflight pipelined requests to clear.
	Expire()
}

// A NonceMaker creates a new Nonce.
type NonceMaker func() (Nonce, error)

// A NonceStore keeps track of currently valid nonces. It needs to handle expiration.
type NonceStore interface {
	Add(nonce Nonce) error
	Lookup(value string) (Nonce, bool, error)
}

// The Digest interface exposes a ServeHTTP method from net/http. On successful
// authentication, nothing happens. On a failure or missing credentials then it
// will invoke http.Error(), afterwhich point you should consider the request
// finished.
type Digest interface {
	EvaluateDigest(params map[string]string, method string) (int, string, bool)
	MakeNonce() (Nonce, error)

	// Turn on logging
	Log(*log.Logger)
}

type digest struct {
	realm      string
	nonces     NonceStore
	nonceMaker NonceMaker
	users      UserStore
	logger     *log.Logger
}

// Create a new Digest.
//
// realm  - Your HTTP Digest realm. Must match that used in your UserStore.Lookup() function or htdigest file.
//
// nonces - Pass nil for the default NonceStore, or implement your own.
//
// nonceMaker - Pass nil for the default, or implement your own.
//
// users - A UserStore. A simple one that uses a map, and a slightly more complicated one that reads
// Apache style htdigest files are included for you to choose from. Or write your own.
func NewDigestHandler(realm string, nonces NonceStore, nonceMaker NonceMaker, users UserStore) Digest {
	if nonces == nil {
		nonces = newSimpleNonceStore()
	}
	if nonceMaker == nil {
		nonceMaker = newSimpleNonce
	}
	if users == nil {
		panic("nil passed for Digest users")
	}
	return &digest{realm: realm,
		nonces:     nonces,
		nonceMaker: nonceMaker,
		users:      users,
	}
}

func (d *digest) Log(on *log.Logger) {
	d.logger = on
}

// The guts of the digest process. It is structured this way to facilitate testing.
// The return is "HTTP status code", "HTTP body", and a flag to say if we need the "stale" added to an
// authorization header on the response.
func (d *digest) EvaluateDigest(params map[string]string, method string) (int, string, bool) {
	user, userOk := params["username"]
	realm, realmOk := params["realm"]
	nonce, nonceOk := params["nonce"]
	response, responseOk := params["response"]
	cnonce, cnonceOk := params["cnonce"]
	qop, qopOk := params["qop"]
	uri, uriOk := params["uri"]
	nc, ncOk := params["nc"]

	if !(userOk && realmOk && nonceOk && responseOk && uriOk) {
		if d.logger != nil {
			d.logger.Printf("required param omitted")
		}
		return http.StatusUnauthorized, "", false
	}

	storedUserRealmPassHash, ok, err := d.users.Lookup(user, realm)

	if !ok {
		if d.logger != nil {
			d.logger.Printf("no such user %v in realm %v", user, realm)
		}
		return http.StatusUnauthorized, "", false
	}
	if err != nil {
		if d.logger != nil {
			d.logger.Printf("no user")
		}
		return http.StatusInternalServerError, fmt.Sprintf("Unable to lookup user: %s", err.Error()), false
	}

	n, ok, err := d.nonces.Lookup(nonce)
	if !ok {
		if d.logger != nil {
			d.logger.Printf("no such nonce: %#v not in %#v", nonce, d.nonces)
		}
		return http.StatusUnauthorized, "", true
	}
	if err != nil {
		return http.StatusInternalServerError, fmt.Sprintf("Error processing nonce: %s", err.Error()), false
	}

	// compute A1
	ha1 := ""

	algorithm, algorithmOk := params["algorithm"]
	if !algorithmOk || algorithm == "MD5" {
		ha1 = storedUserRealmPassHash
	} else if algorithm == "MD5-sess" {
		if !cnonceOk {
			return http.StatusBadRequest, "MD5-sess digest without cnonce", false
		}
		v := md5.Sum([]byte(storedUserRealmPassHash + ":" + nonce + ":" + cnonce))
		ha1 = hex.EncodeToString(v[:])
		// we could store ha1 under nonce+cnonce I suppose, that seems to be the intent
		// of the RFC.
	} else {
		return http.StatusNotImplemented, fmt.Sprintf("Unsupported digest algorithm: %s", algorithm), false
	}

	if len(ha1) != 2*md5.Size {
		return http.StatusInternalServerError, fmt.Sprintf("Invalid digest HA1: len=%d", len(ha1)), false
	}

	// compute A2
	ha2 := ""

	if !qopOk || qop == "auth" {
		h := md5.Sum([]byte(method + ":" + uri))
		ha2 = hex.EncodeToString(h[:])
	} else if qop == "auth-int" {
		// Will need to read body, undo transfer encoding, and stick it back in to Request. Ick.
		// I should also point out that libcurl doesn't support auth-int, so validating is going to be rough. Opera
		// is rumored to be the only major browser to support auth-int, according to the internet in 2014
		return http.StatusNotImplemented, fmt.Sprintf("Unsupported digest qop: %s", qop), false
	} else {
		return http.StatusNotImplemented, fmt.Sprintf("Unsupported digest qop: %s", qop), false
	}

	if len(ha2) != 2*md5.Size {
		return http.StatusInternalServerError, fmt.Sprintf("Invalid digest HA2: len=%d", len(ha2)), false
	}

	calculatedResponse := ""

	if !qopOk {
		mm := md5.New()
		mm.Write([]byte(ha1))
		mm.Write([]byte(":" + nonce + ":"))
		mm.Write([]byte(ha2))
		calculatedResponse = hex.EncodeToString(mm.Sum([]byte{}))
	} else if qop == "auth" || qop == "auth-int" {
		if !ncOk {
			return http.StatusBadRequest, "Digest auth or auth-int is missing nc", false
		}
		ncVal, err := strconv.ParseUint(nc, 16, 32)
		if err != nil {
			return http.StatusBadRequest, "Invalid digest nc", false
		}
		if !n.AcceptCounter(uint(ncVal)) {
			return http.StatusUnauthorized, "Digest nc was not valid", true
		}

		r := ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2
		rr := md5.Sum([]byte(r))
		calculatedResponse = hex.EncodeToString(rr[:])
	} else {
		return http.StatusNotImplemented, fmt.Sprintf("Unsupported digest qop: %s", qop), false
	}
	if len(calculatedResponse) != 2*md5.Size {
		return http.StatusInternalServerError, fmt.Sprintf("Miscalculated digest response: %#v", calculatedResponse), false
	}

	n.Next()

	// resist timing attacks, at least here. At this one line.
	if subtle.ConstantTimeCompare([]byte(response), []byte(calculatedResponse)) == 1 {
		return http.StatusOK, "", false
	}

	return http.StatusUnauthorized, "", false
}

func (d *digest) MakeNonce() (Nonce, error) {
	n, err := d.nonceMaker()
	if err != nil {
		return nil, err
	}

	if err := d.nonces.Add(n); err != nil {
		return nil, err
	}

	return n, nil
}
