package transformrequest

import (
	"encoding/json"
	"errors"
	// "fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type RedisFunc struct{}

type SecurityContext struct {
	User               string
	Email              string
	Scope              Scope
	AuthenticationType string
	Roles              []string
}

type Scope struct {
	Cids []string
}

func (f RedisFunc) Transform(r *http.Request) (*http.Request, error) {
	if r.RequestURI == "/version" {
		return r, nil
	}

	var routeExp = regexp.MustCompile(`ids/v1/cids/(?P<cid>[[:alnum:]]+)/entity_types/(?P<entitytype>[[:alnum:]]+)/domains/(?P<domain>[[:alnum:]\-_\.]+)/keys/(?P<key>[[:alnum:]]+)`)
	routeMatch := routeExp.FindStringSubmatch(r.RequestURI)
	if len(routeMatch) != 5 {
		return r, errors.New("Missing path parameters")
	}

	result := make(map[string]string)
	for i, name := range routeExp.SubexpNames() {
		if i != 0 {
			result[name] = routeMatch[i]
		}
	}

	r.ParseForm()
	securityContextText := r.Form["security_context"]

	if securityContextText == nil {
		return r, errors.New("Security Context missing, Cid access can't be authenticated")
	} else {

		var securityContext SecurityContext
		json.Unmarshal([]byte(securityContextText[0]), &securityContext)
		delete(r.Form, "security_context")

		found := false
		allowedCids := securityContext.Scope.Cids
		for _, allowedCid := range allowedCids {
			if allowedCid == result["cid"] {
				found = true
			}
		}
		if !found {
			return r, errors.New("Cid not allowed for this user")
		}
	}

	redisKey := result["cid"] + ":" + result["entitytype"] + ":" + result["domain"] + ":" + result["key"]
	redisMap := make(map[string][]string)

	if r.Method == "GET" {
		redisMap["GETALL"] = append(redisMap["GETALL"], redisKey)
	}

	if r.Method == "PUT" {
		kvs := ""
		// TODO: assuming that query param keys will not be repeated, do I need to check for this?
		for k, v := range r.Form {
			if v[0][len(v[0])-1:] == "," { //looking at a list
				if len(v[0]) > 1 { //keep from attempting to push empty list
					lpushParams := redisKey + ":" + k + " " + strings.Replace(v[0], ",", " ", -1)
					redisMap["RPUSH"] = append(redisMap["RPUSH"], lpushParams[:len(lpushParams)-1])
				}

			} else {
				kvs += k + " " + v[0] + " "
			}
			delete(r.Form, k)
		}
		kvs += "last_update " + time.Now().Format(time.RFC3339)
		redisMap["HMSET"] = append(redisMap["HMSET"], redisKey+":kvs "+kvs)
		// TODO: what happens on a PUT with no values? shout it still input last_update?
	}

	if r.Method == "PATCH" {
		// TODO: assuming that query param keys will not be repeated, do I need to check for this?
		for k, v := range r.Form {
			keyCheck := regexp.MustCompile(`^[[:alpha:]][[:alnum:]_]*$`)
			keyMatch := keyCheck.FindStringSubmatch(k)
			if len(keyMatch) == 0 {
				return r, errors.New("Could not parse request")
			}
			// TODO: are there any checks I need to run on values?
			// if something seems comma delimited but does not end in comma is it encoded as string?
			// what if values have parenthesis or other symbols like $?

			if v[0][len(v[0])-1:] == "," { // new list to put under key
				if len(v[0]) > 1 {
					lpushParams := redisKey + ":" + k + " " + strings.Replace(v[0], ",", " ", -1)
					redisMap["PUSH"] = append(redisMap["PUSH"], lpushParams[:len(lpushParams)-1])
				}
				//TODO: what happens on an LPUSH with no items in the list? should this become a DELETE?

			} else {
				var commandParenthesisExp = regexp.MustCompile(`^\$([A-Z]+)\((.*)\)$`)
				parenthesisMatch := commandParenthesisExp.FindStringSubmatch(v[0])
				if len(parenthesisMatch) != 3 {

					var commandExp = regexp.MustCompile(`^\$([A-Z]+)$`)
					commandMatch := commandExp.FindStringSubmatch(v[0])
					if len(commandMatch) == 0 {
						redisMap["HSET"] = append(redisMap["HSET"], redisKey+":kvs "+k+" "+v[0])

					} else {
						commandName := commandMatch[1]

						if commandName == "DELETE" {
							redisMap["HDEL"] = append(redisMap["HDEL"], redisKey+":kvs "+k)

						} else if commandName == "INCR" {
							redisMap["HINCRBY"] = append(redisMap["HINCRBY"], redisKey+":kvs "+k+" 1")

						} else {
							return r, errors.New("Could not parse request")
						}
					}
				} else { // commands with parenthesis
					commandName := parenthesisMatch[1]
					commandValue := parenthesisMatch[2]
					pushParams := redisKey + ":" + k + " " + strings.Replace(commandValue, ",", " ", -1)

					// TODO: does prepend or append allow for ending comma? or is it a bad request?
					if commandName == "PREPEND" {
						redisMap["LPUSH"] = append(redisMap["LPUSH"], pushParams)
						//parameters = append(parameters, pushParams[:len(pushParams)-1])

					} else if commandName == "APPEND" {
						redisMap["RPUSH"] = append(redisMap["RPUSH"], pushParams)
						//parameters = append(parameters, pushParams[:len(pushParams)-1])

					} else if commandName == "ADD" {
						if _, err := strconv.ParseFloat(commandValue, 64); err != nil {
							return r, errors.New("ADD value was not a float")
						} else {
							redisMap["HINCRBYFLOAT"] = append(redisMap["HINCRBYFLOAT"], redisKey+":kvs "+k+" "+commandValue)
						}

					} else {
						return r, errors.New("Could not parse request")
					}
				}
			}
			delete(r.Form, k)
		}
		redisMap["HSET"] = append(redisMap["HSET"], redisKey+":kvs last_update "+time.Now().Format(time.RFC3339))
	}

	if r.Method == "DELETE" {
		redisMap["DELALL"] = append(redisMap["DELALL"], redisKey)
	}

	for c, p := range redisMap {
		r.Form[c] = p
	}
	return r, nil
}
