package basicauth

import (
	"net/http"
	"strings"
)

// UserPass holds user[password] for all authentication users.
type UserPass struct {
	users map[string]string
}

func New() *UserPass {
	return &UserPass{users: make(map[string]string)}
}

func (up *UserPass) AddUser(username, password string) {
	up.users[username] = password
}

func (up *UserPass) DeleteUser(username string) {
	delete(up.users, username)
}

// Auth performs basic authentication using http Basic realm.
func (up *UserPass) Auth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		u, p, ok := req.BasicAuth()
		if !ok || len(strings.TrimSpace(u)) < 1 || len(strings.TrimSpace(p)) < 1 {
			unauthorised(w)
			return
		}

		pass, ok := up.users[u]
		if !ok || pass != p {
			unauthorised(w)
			return
		}

		fn(w, req)
	}
}

func unauthorised(rw http.ResponseWriter) {
	rw.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
	rw.WriteHeader(http.StatusUnauthorized)
}
