package main

import (
	"errors"
	"net/http"
)

// All ordinary form fields are scalar. The selected card IDs are the only list.
func parseScalarForm(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	for key, values := range r.PostForm {
		if len(values) > 1 && !(r.URL.Path == "/" && key == "ids" && (r.PostForm.Get("action") == "batch-unbind" || r.PostForm.Get("action") == "batch-revoke")) {
			return errors.New("duplicate form field")
		}
	}
	return nil
}
