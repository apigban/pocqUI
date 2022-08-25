package context

import (
	"context"

	"github.com/apigban/pocqUI/pkg/models"
)

const (
	userKey privateKey = "user"
)

type privateKey string

// Set a user to a context object
func WithUser(ctx context.Context, user *models.User) context.Context {
	return context.WithValue(ctx, userKey, user)
}

func User(ctx context.Context) *models.User {

	//	if User is in context assign user to tempconst
	if temp := ctx.Value(userKey); temp != nil { // pull user key from ctx and ssign to temp
		if user, ok := temp.(*models.User); ok { // check if data in temp is of type models.User
			return user
		}
	}
	//	if user is not present in context, return no user
	return nil
}
