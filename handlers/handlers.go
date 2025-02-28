package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rjs-creates/movie-picker/internal"
	"github.com/rjs-creates/movie-picker/models"
	"golang.org/x/crypto/bcrypt"
)

var users = map[string]models.Login{}
var AuthError = errors.New("Authorization error")

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(password) < 8 {
		http.Error(w, "Username or password of invalid length", http.StatusBadRequest)
		return
	}

	if _, ok := users[username]; ok {
		http.Error(w, "User Already Exists", http.StatusConflict)
		return
	}

	hashedPassword, err := internal.HashedPassword(password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	users[username] = models.Login {
		HashedPassword: hashedPassword,
	}
	fmt.Fprintf(w, "Successfully registered user %s", username)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	
	err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	sessionToken, err := internal.GenerateToken()
	if err != nil {
		http.Error(w, "Error creating session token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	csrfToken, err := internal.GenerateToken()
	if err != nil {
		http.Error(w, "Error creating CSRF token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
	})

	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintf(w, "Successfully logged in user %s", username)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
	}

	err:= authorize(w, r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
		return		
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	user.SessionToken = ""
	user.CSRFToken = ""	
	users[username] = user

	fmt.Fprint(w, "Successfully logged out")
}

func Protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
	}
	if err := authorize(w, r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := r.FormValue("username")
	fmt.Fprintf(w, "Welcome %s", username)
}

func authorize(w http.ResponseWriter, r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		fmt.Println(w, "Erroring here")
		return AuthError
	}

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		fmt.Println(w, "Erroring here 2")
		return AuthError
	}

	csrf := r.Header.Get("X-CSRF-Token")
	if csrf == "" || csrf != user.CSRFToken {
		fmt.Printf("Input CSRF: %s vs User CSRF: %s\n", csrf, user.CSRFToken)
		return AuthError
	}

	return nil
}