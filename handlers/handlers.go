package handlers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/rjs-creates/movie-picker/models"
)

var users = []models.Login{}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got /hello request\n")
	io.WriteString(w, "Hello, HTTP!\n")
}