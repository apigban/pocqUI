package views

const (
	AlertLvlError   = "danger"
	AlertLvlWarning = "warning"
	AlertLvlInfo    = "info"
	AlertLvlSuccess = "success"

	// Catchall message
	AlertMsgGeneric = "Something went wrong. Please try again. Contact us if the problem persists."
)

// Alert is used to rendned Bootstrap Alert messages in templates
type Alert struct {
	Level   string
	Message string
}

// Data is the top level structure that views expect data
// to come in
type Data struct {
	Alert *Alert
	Yield interface{}
}

func (d *Data) SetAlert(err error) {
	if pubErr, ok := err.(PublicError); ok { // Type assertion
		d.Alert = &Alert{
			Level:   AlertLvlError,
			Message: pubErr.Public(), // if an error has implements the PublicError interface, display the error to end user
		}
	} else {
		d.Alert = &Alert{
			Level:   AlertLvlError,
			Message: AlertMsgGeneric, // show generic error error to enduser
		}
	}
	// TODO - handle errors that are presented to the user as generic ones
	// TODO - log alerts that are privateErrors

}

func (d *Data) AlertError(msg string) {
	d.Alert = &Alert{
		Level:   AlertLvlError,
		Message: AlertMsgGeneric, // show generic error error to enduser
	}
}

type PublicError interface {
	error
	Public() string
}
