package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"
)

func TestAppError_Error(t *testing.T) {
	should.Equal(t, "boom", (&AppError{Message: "boom"}).Error())
	should.Equal(t, "boom: root cause",
		(&AppError{Message: "boom", Cause: errors.New("root cause")}).Error())
}

func TestRenderContent(t *testing.T) {
	t.Run("nil_renders_empty_object", func(t *testing.T) {
		rec := httptest.NewRecorder()

		err := RenderContent(nil, rec, http.StatusOK)

		must.NoError(t, err)
		should.Equal(t, http.StatusOK, rec.Code)
		should.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
		should.Equal(t, "{}", rec.Body.String())
	})

	t.Run("struct_is_json_encoded", func(t *testing.T) {
		rec := httptest.NewRecorder()

		err := RenderContent(map[string]string{"a": "b"}, rec, http.StatusCreated)

		must.NoError(t, err)
		should.Equal(t, http.StatusCreated, rec.Code)
		should.JSONEq(t, `{"a":"b"}`, rec.Body.String())
	})
}

func TestAppHandler_ServeHTTP(t *testing.T) {
	t.Run("error_without_equivalence", func(t *testing.T) {
		h := AppHandler(func(w http.ResponseWriter, r *http.Request) *AppError {
			return &AppError{Message: "bad request", Code: http.StatusBadRequest}
		})
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		should.Equal(t, http.StatusBadRequest, rec.Code)
		should.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
		should.JSONEq(t, `{"message":"bad request"}`, rec.Body.String())
	})

	// Regression guard for the equivalence-serialization fix: a duplicate
	// redemption must surface the equivalence field in the JSON envelope.
	t.Run("error_with_equivalence_is_serialized", func(t *testing.T) {
		h := AppHandler(func(w http.ResponseWriter, r *http.Request) *AppError {
			return &AppError{Message: "duplicate", Code: http.StatusConflict, Equivalence: "id"}
		})
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		should.Equal(t, http.StatusConflict, rec.Code)
		should.JSONEq(t, `{"message":"duplicate","equivalence":"id"}`, rec.Body.String())
	})

	t.Run("nil_error_leaves_handler_response_untouched", func(t *testing.T) {
		h := AppHandler(func(w http.ResponseWriter, r *http.Request) *AppError {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return nil
		})
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		should.Equal(t, http.StatusOK, rec.Code)
		should.Equal(t, "ok", rec.Body.String())
	})
}
