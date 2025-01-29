package main

import (
	"net/http"
	"github.com/rjs-creates/movie-picker/routes"
)

func main() {
	router := routes.SetupRoutes()
	http.ListenAndServe(":8080", router)
}