# auth/htpasswd [![GoDoc](https://godoc.org/github.com/jimstudt/http-authentication/basic?status.png)](http://godoc.org/github.com/jimstudt/http-authentication/basic)

Authenticate using Apache-style htpasswd files and HTTP Basic Authentication.

`htpasswd` has supported a number of different password hashing schemes over the
decades. Most common and sane ones are supported directly. For some you will need
to add another package.

| Style | Status |
|-------|--------|
| plain | yes+   |
| md5   | yes    |
| sha   | yes    |
| crypt | no (conflicts with plain)     |
| bcrypt | no (can add with another package)   |

The standard set of systems will use *Plain*, *Sha*, and *MD5* systems while filtering out *bcrypt*.
Because of its complexity, *bcrypt* will be in another package which you can import and
add if you need it. *Plain* accepts both Apache style plain text and nginx style where the 
password is preceded by {PLAIN}.

## Usage

~~~ go
import (
  "github.com/codegangsta/martini"
  "github.com/jimstudt/http-authentication/basic"
  "log"
)

func main() {
  m := martini.Classic()

  pw,err := basic.New("My Realm", "./my-htpasswd-file", htpasswd.DefaultSystems, nil)
  if ( err != nil) {
    log.Fatalf("Unable to read my htpassword file: %s", err.Error())
  }

  // authenticate every request
  m.Use( pw.ServeHTTP)

  // You will also want to call pw.Reload(nil) to reprocess the password file when it changes.

  // You can use pw.ReloadOn( syscall.SIGHUP, nil ) to make it automatically
  // reload on a HUP signal.

  // And those 'nil' arguments are where you pass a function to be notified about illegally 
  // formatted entries, or unsupported hash systems. See the API documents.

  // If you only want to authenticate some requests, then it goes like this...
  //    m.Get("/secure/thing", pw.ServeHTTP, myRealHandler)
  // ... if pw.ServeHTTP does the 401 then your handler will not be called
 
  m.Run()

}
~~~

## API Documentation

The API is documented using godoc and also available at [godoc.org](http://godoc.org/github.com/jimstudt/http-authentication/basic)
~~~



