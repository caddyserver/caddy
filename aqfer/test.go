package main

import (
	"fmt"
	"github.com/garyburd/redigo/redis"
	"net/http"
)

func main() {
	http.HandleFunc("/", Auth)
	http.ListenAndServe(":8081", nil)
}

var address string
var pool redis.Pool
var conn redis.Conn

func init() {
	address = "elasticacheaqfer2.elwwyl.0001.use1.cache.amazonaws.com:6379"

	pool = redis.Pool{
		MaxIdle:   80,
		MaxActive: 120000,
		Dial: func() (redis.Conn, error) {
			if conn, err := redis.Dial("tcp", address); err != nil {
				fmt.Println(err)
				return nil, err
			} else {
				return conn, nil
			}
		},
	}
}

func Auth(w http.ResponseWriter, r *http.Request) {
	redis := false
	if redis {
		// conn.Send("GET", "c016cookieasdfasdf1")
		// conn.Flush()
		// getval, err := conn.Receive()

		conn = pool.Get()
		getval, err := conn.Do("GET", "c016cookieasdfasdf1")
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(400)

		} else {
			fmt.Sprintf("%s", getval)
			w.WriteHeader(200)
			// w.Write([]byte(r))
		}

	} else {
		w.WriteHeader(200)
	}
	return
}
