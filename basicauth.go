package basicauth

import "net/http"

// Auth middleware for basic authentication.
func Auth(h http.HandlerFunc, requiredUser, requiredPassword string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the Basic Authentication credentials
		user, password, hasAuth := r.BasicAuth()

		if hasAuth && user == requiredUser && password == requiredPassword {
			// Delegate request to the given handle
			h(w, r)
		} else {
			// Request Basic Authentication otherwise
			w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
	}
}

// LogoutHandler for basic auth.
func LogoutHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
