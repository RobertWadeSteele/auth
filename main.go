package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	id       int
	username string
	hash     string
}

var db = sqlx.MustOpen("sqlite3", "./auth.db")

type AuthHandler struct{}

var loginTmpl = template.Must(template.ParseFiles("login.html"))

func (h AuthHandler) WrapHandler(n http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.ServeHTTP(w, r)
	})
}

func RenderLogin(w http.ResponseWriter, r *http.Request) {
	loginTmpl.Execute(w, nil)
}

func AuthorizeWithUserPass(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Authorize")
	if r.Method == http.MethodPost {
		r.ParseForm()

		user := strings.Join(r.Form["username"], "")
		pass := strings.Join(r.Form["password"], "")

		row := db.QueryRow("SELECT hash FROM users WHERE username=?", user)
		var hash string
		row.Scan(&hash)

		err := ValidatePasswordWithHash(pass, hash)

		if err != nil {
			http.Error(w, "Failed to validate with password.", http.StatusForbidden)
		} else {
			fmt.Fprint(w, "Success!")
		}

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func HashAndSaltPassword(pass string) (string, error) {
	bytes := []byte(pass)
	hash, err := bcrypt.GenerateFromPassword(bytes, bcrypt.DefaultCost)

	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func ValidatePasswordWithHash(pass, hash string) error {
	passBytes := []byte(pass)
	hashBytes := []byte(hash)

	err := bcrypt.CompareHashAndPassword(hashBytes, passBytes)

	if err != nil {
		return err
	}
	return nil
}

func SensitiveInformation(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Sensitive information...")
}

func main() {
	apimux := http.NewServeMux()
	apimux.HandleFunc("/auth", AuthorizeWithUserPass)

	authmux := http.NewServeMux()
	authmux.HandleFunc("/sensitive", SensitiveInformation)

	publicmux := http.NewServeMux()
	publicmux.Handle("/login", http.HandlerFunc(RenderLogin))
	publicmux.Handle("/api/", http.StripPrefix("/api", apimux))

	log.Fatal(http.ListenAndServe(":8080", publicmux))
}
