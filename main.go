package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"

	"github.com/dchest/uniuri"
)

var (
	// Initialize gorm DB
	gormDB, _ = gorm.Open("sqlite3", "sample.db")
)

var (
	oauthConfig = &oauth2.Config{
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		ClientID:     os.Getenv("OAUTH2_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH2_CLIENT_SECRET"),
		Endpoint:     github.Endpoint,
	}
	oauthStateString = "random per user"
)

func handleMain(w http.ResponseWriter, r *http.Request) {
	// TODO reverse proxy everything else, probably requires wildcard matching or something
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// TODO needs to actually be random per user
	oauthStateString = uniuri.NewLen(32)
	url := oauthConfig.AuthCodeURL(oauthStateString)
	log.Print("redirecting to " + url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		log.Print("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	token, err := oauthConfig.Exchange(oauth2.NoContext, code) // TODO: no context?
	if err != nil {
		log.Print("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// get user
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Add("Authorization", "token "+token.AccessToken)
	req.Header.Add("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Print("Error on response: ", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Print("could not read all of resp.Body!")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	err = ioutil.WriteFile("response.raw", contents, 0644)
	if err != nil {
		panic(err)
	}

	log.Print(w, "Content: %s\n", contents)
}

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login/", handleLogin)
	http.HandleFunc("/callback/", handleCallback)

	log.Print("I'm up!")
	log.Fatal(http.ListenAndServe(":9000", nil))
}
