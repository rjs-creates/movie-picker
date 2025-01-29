package routes

import (
	"github.com/gorilla/mux"
	"github.com/rjs-creates/movie-picker/handlers"
)

func SetupRoutes() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/register", handlers.RegisterUser)
	router.HandleFunc("/login", handlers.RegisterUser)
	router.HandleFunc("/logout", handlers.RegisterUser)
	router.HandleFunc("/protected", handlers.RegisterUser)

	return router
}