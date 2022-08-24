package middleware

import (
	"fmt"
	"net/http"

	"github.com/apigban/lenslocked_v1/context"
	"github.com/apigban/lenslocked_v1/models"
)

type RequireUser struct {
	models.UserService
}

func (mw *RequireUser) Apply(next http.Handler) http.HandlerFunc {
	return mw.ApplyFn(next.ServeHTTP)
}

func (mw *RequireUser) ApplyFn(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Redirect user to Login page if cookie is not found
			cookie, err := r.Cookie("remember_token")
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			// Redirect user to Login page if remember_token is not found
			user, err := mw.ByRemember(cookie.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			ctx := r.Context() // set current context

			ctx = context.WithUser(ctx, user) // update the current context with the user associated to remember_token
			r = r.WithContext(ctx)            // update request to have the updated context

			fmt.Println("User Found:", user)

			next(w, r)
		})
}
