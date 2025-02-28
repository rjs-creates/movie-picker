package routes

import (
	"github.com/gorilla/mux"
	"github.com/rjs-creates/movie-picker/handlers"
)

func SetupRoutes() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/register", handlers.RegisterUser)
	router.HandleFunc("/login", handlers.Login)
	router.HandleFunc("/logout", handlers.Logout)
	router.HandleFunc("/protected", handlers.Protected)

	return router
}	