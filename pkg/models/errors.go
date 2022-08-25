package models

import "strings"

const (
	// ErrNotFound is returned when a resource is not found in the database
	ErrNotFound modelError = "models: resource not found"

	ErrPasswordIncorrect modelError = "models: incorrect password provided"

	// ErrEmailRequired is returned when no email address is provided
	// when a user is created
	ErrEmailRequired modelError = "models: email address is required"

	// ErrEmailInvalid is returned when an email address provided does
	// not match any of our formatting requirements
	ErrEmailInvalid modelError = "models: email address provided is invalid"

	// ErrEmailTaken is returned when an update or create is attempted
	// with an email address that is already in use.
	ErrEmailTaken modelError = "models: email address is already taken"

	// ErrPasswordTooShort is returned when an update or create is
	// attempted with a password <8 characters.
	ErrPasswordTooShort modelError = "models: password must be atleast 8 characters long"

	// ErrPasswordRequired is returned when a create is attempted without a password
	ErrPasswordRequired modelError = "models: password is required"

	ErrTitleRequired modelError = "models: title is required"

	// ErrIDInvalid is returned when an invalid ID is provided to a method like Delete()
	ErrIDInvalid privateError = "models: ID provided was invalid"

	// ErrRememberTooShort is returned when a remember token is not atlease 32 bytes in length
	ErrRememberTooShort privateError = "models: remember token must be atleast 32 bytes long"

	// ErrRememberRequired is returned when a create or update is attempted without
	// without a user remember token hash
	ErrRememberRequired privateError = "models: remember token is required"

	ErrUserIDRequired privateError = "models: user ID is required"
)

type modelError string

func (e modelError) Error() string {
	return string(e)
}

// Public modifies an error to be publicly displayed.
// Capitalizes the first character of the string
// after prefix is trimmed
func (e modelError) Public() string {
	s := strings.Replace(string(e), "models: ", "", 1)
	split := strings.Split(s, " ")
	split[0] = strings.Title(split[0])
	return strings.Join(split, " ")
}

type privateError string

func (e privateError) Error() string {
	return string(e)
}
