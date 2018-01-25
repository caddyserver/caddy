package transformrequest

import (
	"net/http"

	"github.com/fellou89/caddy-transformrequest/functions"
)

var Functions map[string]Function

func init() {
	Functions = make(map[string]Function)

	Functions["redis"] = transformrequest.RedisFunc{}
	Functions["dynamo"] = transformrequest.DynamoFunc{}
}

type Function interface {
	Transform(r *http.Request) (*http.Request, error)
}

func Transformations(r *http.Request) (*http.Request, error) {
	// r.ParseForm()

	// if r.Form["backend"][0] == "redis" {
	// 	return functions["redis"].Transform(r)
	// }
	// if r.Form["backend"][0] == "dynamo" || r.Form["backend"][0] == "dax" {
	// 	return functions["dynamo"].Transform(r)
	// }

	// return r, nil
	return Functions["redis"].Transform(r)
}
