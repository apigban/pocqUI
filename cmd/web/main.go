package main

import (
	"fmt"
	"net/http"

	"github.com/apigban/lenslocked_v1/controllers"
	"github.com/apigban/lenslocked_v1/middleware"
	"github.com/apigban/lenslocked_v1/models"
	"github.com/gorilla/mux"
)

// TODO - Fix before prod
const (
	host     = "localhost"
	port     = 5432
	user     = "PGUSER"
	password = "PASSWORD"
	dbname   = "lenslocked_test"
)

func main() {
	// TODO - Fix before prod
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	services, err := models.NewServices(psqlInfo)
	must(err)
	// TODO - FIX below, it doesnt compile because Close(), AutoMigrate() and DestructiveReset() have not been moved to the top level service
	// Additional note - the 3 methods are general to all services, it is proper to only have 1 top level set of methods
	// instead of repeating Close(), AutoMigrate() and DestructiveReset() for every service
	defer services.Close()
	services.AutoMigrate()
	// services.DestructiveReset()

	staticC := controllers.NewStatic()
	usersC := controllers.NewUsers(services.User)
	galleriesC := controllers.NewGalleries(services.Gallery)
	requireUserMw := middleware.RequireUser{UserService: services.User}

	r := mux.NewRouter()
	r.Handle("/", staticC.Home).Methods("GET")
	r.Handle("/contact", staticC.Contact).Methods("GET")
	r.HandleFunc("/signup", usersC.New).Methods("GET")
	r.HandleFunc("/signup", usersC.Create).Methods("POST")
	r.Handle("/login", usersC.LoginView).Methods("GET")
	r.HandleFunc("/login", usersC.Login).Methods("POST")
	r.HandleFunc("/cookietest", usersC.CookieTest).Methods("GET")

	// Gallery Routes
	r.Handle("/galleries/new", requireUserMw.Apply(galleriesC.New)).Methods("GET")
	r.HandleFunc("/galleries", requireUserMw.ApplyFn(galleriesC.Create)).Methods("POST")

	fmt.Println("Starting the server on :3000...")
	http.ListenAndServe(":3000", r)

}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
