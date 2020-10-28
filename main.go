package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	gormDB, _ = gorm.Open("sqlite3", "sample.db")
)

var (
	oauthConfig = &oauth2.Config{
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		ClientID:     os.Getenv("OAUTH2_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH2_CLIENT_SECRET"),
		Endpoint:     github.Endpoint,
	}
)

type GithubUserDTO struct {
	Login string `json:login`
	Id    int    `json:id`
	Name  string `json:name`
}

type BearerTokenDTO struct {
	Token string `json:token`
}

type User struct {
	gorm.Model

	OAuth2Provider string
	ExternalId     int
	Name           string
	Login          string
	BearerToken    string
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateRandomString(s int) string {
	b, err := GenerateRandomBytes(s)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func getBearerTokenFromRequest(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if len(auth) == 0 {
		return "", fmt.Errorf("no Authorization header")
	}

	bearer_slice := strings.Split(auth, " ")
	if len(bearer_slice) != 2 {
		return "", fmt.Errorf("malformed Authorization header")
	}

	bearer_key, bearer_value := bearer_slice[0], bearer_slice[1]
	if strings.ToLower(bearer_key) != "bearer" {
		return "", fmt.Errorf("malformed Bearer section")
	}

	return bearer_value, nil
}

func getUserForValidBearerToken(bearer_token string) (*User, error) {
	// check for a user corresponding to that bearer token
	tx := gormDB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	var u *User = &User{}
	u.BearerToken = bearer_token

	tx.First(u)

	if u.ExternalId == 0 {
		return nil, fmt.Errorf("no user")
	}

	if u.BearerToken != bearer_token {
		return nil, fmt.Errorf("no user")
	}

	return u, nil
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	// check for valid bearer token, get user
	bearer_token, err := getBearerTokenFromRequest(r)
	if err != nil {
		log.Printf("handleMain error " + err.Error())
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	u, err := getUserForValidBearerToken(bearer_token)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 Unauthorized"))
		return
	}

	// past here, the user is valid - proxy
	upstream := "http://127.0.0.1:12345"
	url, _ := url.Parse(upstream)
	proxy := httputil.NewSingleHostReverseProxy(url)

	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme
	r.Host = url.Host

	r.Header.Set("X-AuthTunnel-ExternalId", fmt.Sprintf("%v", u.ExternalId))
	r.Header.Set("X-AuthTunnel-Name", fmt.Sprintf("%v", u.Name))
	r.Header.Set("X-AuthTunnel-Login", fmt.Sprintf("%v", u.Login))

	proxy.ServeHTTP(w, r)
}

func handleWhoami(w http.ResponseWriter, r *http.Request) {
	// check for valid bearer token, get user
	bearer_token, err := getBearerTokenFromRequest(r)
	if err != nil {
		log.Printf("handleMain error " + err.Error())
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	u, err := getUserForValidBearerToken(bearer_token)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 Unauthorized"))
		return
	}

	result, err := json.Marshal(u)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("bad marshal!"))
		return
	}

	w.Write(result)
}

func oauthStateStringFromRequest(r *http.Request) string {
	hash := sha256.New()

	hash.Write([]byte(r.Header.Get("User-Agent")))

	for _, cookie := range r.Cookies() {
		hash.Write([]byte(cookie.Name))
		hash.Write([]byte(cookie.Value))
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	oauthStateString := oauthStateStringFromRequest(r)
	log.Print("computed oauthStateString as " + oauthStateString)

	url := oauthConfig.AuthCodeURL(oauthStateString)
	log.Print("redirecting to " + url)
	http.Redirect(w, r, url, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	oauthStateString := oauthStateStringFromRequest(r)
	state := r.FormValue("state")
	if state != oauthStateString {
		log.Print("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	code := r.FormValue("code")
	token, err := oauthConfig.Exchange(oauth2.NoContext, code) // TODO: no context?
	if err != nil {
		log.Print("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusFound)
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
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Print("could not read all of resp.Body!")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	var userDTO GithubUserDTO
	if err := json.Unmarshal(contents, &userDTO); err != nil {
		log.Print("Could not unmarshal contents! %v", contents)
		return
	}

	log.Printf("Saw user DTO values %v, %v, %v", userDTO.Login, userDTO.Id, userDTO.Name)

	tx := gormDB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	var u User

	tx.First(&u, "external_id = ?", userDTO.Id)
	if u.ExternalId != userDTO.Id {
		log.Printf("Creating new user entry")
		u = User{
			OAuth2Provider: "Github",
			ExternalId:     userDTO.Id,
			Name:           userDTO.Name,
			Login:          userDTO.Login,
			BearerToken:    GenerateRandomString(64),
		}
	} else {
		log.Printf("Pulled existing user entry")
	}

	b := BearerTokenDTO{
		Token: u.BearerToken,
	}

	tx.Save(&u)
	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b)
}

func main() {
	gormDB.AutoMigrate(&User{})

	http.HandleFunc("/", handleMain)
	http.HandleFunc("/whoami", handleWhoami)
	http.HandleFunc("/login/", handleLogin)
	http.HandleFunc("/callback/", handleCallback)

	log.Print("I'm up!")
	log.Fatal(http.ListenAndServe(":9000", nil))
}
