package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// AppError defines an application error with cause, message and HTTP status code
type AppError struct {
	Cause   error  `json:"-"`
	Message string `json:"message"`
	Code    int    `json:"-"`
}

// Error returns the error message
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s", e.Message, e.Cause.Error())
	}
	return e.Message
}

// WrapError creates a new AppError from an error
func WrapError(err error, message string, code int) *AppError {
	return &AppError{
		Cause:   err,
		Message: message,
		Code:    code,
	}
}

// RenderContent renders JSON content with appropriate status code
func RenderContent(content any, w http.ResponseWriter, statusCode int) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if content == nil {
		// Return empty JSON object instead of null
		_, err := w.Write([]byte("{}"))
		return err
	}
	return json.NewEncoder(w).Encode(content)
}

// AppHandler is a custom HTTP handler type that returns an AppError
type AppHandler func(http.ResponseWriter, *http.Request) *AppError

// ServeHTTP makes AppHandler satisfy the http.Handler interface
func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := fn(w, r); err != nil {
		// Log the error
		if logger, ok := r.Context().Value("logger").(*slog.Logger); ok && err.Cause != nil {
			logger.Error("handler error",
				slog.String("message", err.Message),
				slog.Any("error", err.Cause))
		}
		// Render the error response
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(err.Code)
		// Create the error response
		errorResponse := map[string]string{"message": err.Message}
		if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
			// If we can't encode the error response, log it and send a plain text error
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}
