package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	config "ftgo-finpro/config/database"
	admin_handler "ftgo-finpro/internal/adminStoreHandler"
)

// Cleanup database after tests
func teardownDBForAdminStore(storeID, adminEmail string) {
	queries := []struct {
		query string
		param interface{}
	}{
		{"DELETE FROM store_admins WHERE email = $1", adminEmail},
		{"DELETE FROM stores WHERE id = $1", storeID},
	}

	for _, q := range queries {
		if _, err := config.Pool.Exec(context.Background(), q.query, q.param); err != nil {
			panic(err)
		}
	}
}

func TestAuthAdminStore(t *testing.T) {
	e := echo.New()

	// Set up test data
	storeID := uuid.New().String()
	adminEmail := "admin.test@example.com"
	adminPassword := "securepassword123"

	// Clean up after tests
	defer teardownDBForAdminStore(storeID, adminEmail)

	// Insert mock store data
	storeQuery := `INSERT INTO stores (id, name, products, product_types) VALUES ($1, $2, $3, $4)`
	storeProducts := `[{"product": "Product A", "price": 10000, "quantity": 50, "weight": 1.5}]`
	productTypes := `["Type A"]`
	_, err := config.Pool.Exec(context.Background(), storeQuery, storeID, "Test Store", storeProducts, productTypes)
	if err != nil {
		t.Fatalf("Failed to insert mock store: %v", err)
	}

	// Define test cases for RegisterStoreAdmin
	t.Run("RegisterStoreAdmin", func(t *testing.T) {
		t.Run("Valid Registration", func(t *testing.T) {
			requestBody := map[string]interface{}{
				"name":     "Test Admin",
				"email":    adminEmail,
				"password": adminPassword,
				"store_id": storeID,
			}
			body, _ := json.Marshal(requestBody)
			req := httptest.NewRequest(http.MethodPost, "/admin/register", bytes.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := admin_handler.RegisterStoreAdmin(c)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, rec.Code)

			response := map[string]interface{}{}
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["message"], "registered successfully")
			assert.Equal(t, adminEmail, response["email"])
		})

		t.Run("Duplicate Registration", func(t *testing.T) {
			requestBody := map[string]interface{}{
				"name":     "Test Admin",
				"email":    adminEmail,
				"password": adminPassword,
				"store_id": storeID,
			}
			body, _ := json.Marshal(requestBody)
			req := httptest.NewRequest(http.MethodPost, "/admin/register", bytes.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := admin_handler.RegisterStoreAdmin(c)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, rec.Code)

			response := map[string]interface{}{}
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["message"], "Email already registered")
		})
	})

	// Define test cases for LoginStoreAdmin
	t.Run("LoginStoreAdmin", func(t *testing.T) {
		t.Run("Valid Login", func(t *testing.T) {
			requestBody := map[string]interface{}{
				"email":    adminEmail,
				"password": adminPassword,
			}
			body, _ := json.Marshal(requestBody)
			req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := admin_handler.LoginStoreAdmin(c)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, rec.Code)

			response := map[string]interface{}{}
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.NotEmpty(t, response["token"])
			assert.Equal(t, adminEmail, response["email"])
		})

		t.Run("Invalid Login - Wrong Password", func(t *testing.T) {
			requestBody := map[string]interface{}{
				"email":    adminEmail,
				"password": "wrongpassword",
			}
			body, _ := json.Marshal(requestBody)
			req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := admin_handler.LoginStoreAdmin(c)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, rec.Code)

			response := map[string]interface{}{}
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["message"], "Invalid email or password")
		})
	})
}
