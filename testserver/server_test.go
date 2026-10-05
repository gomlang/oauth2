package testserver

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestIndependentOracleRejectsMissingCredentials(t *testing.T) {
	s := Start(false)
	defer Close(s)
	req, _ := http.NewRequest("POST", URL(s)+"/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal(r.StatusCode)
	}
}
func TestIndependentOracleAcceptsFormEncodedBasic(t *testing.T) {
	s := Start(false)
	defer Close(s)
	r, _ := http.NewRequest("POST", URL(s)+"/token", strings.NewReader("grant_type=client_credentials"))
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape("client :+é"), url.QueryEscape("secret :+é"))
	res, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
}
