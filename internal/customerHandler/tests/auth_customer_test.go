package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	config "ftgo-finpro/config/database"
	customer_handler "ftgo-finpro/internal/customerHandler"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// Cleanup database after tests
func teardownDB(pool *pgxpool.Pool) {
	query := "DELETE FROM customers WHERE email = $1"
	_, err := pool.Exec(context.Background(), query, "john.doe@example.com")
	if err != nil {
		panic(err)
	}
	pool.Close() // Close the connection pool to avoid reuse
}

// Test for RegisterCustomer
func TestRegisterCustomer(t *testing.T) {
	e := echo.New()

	// Mock request payload
	requestPayload := map[string]string{
		"name":     "John Doe",
		"email":    "john.doe@example.com",
		"password": "Password123",
	}
	requestBody, _ := json.Marshal(requestPayload)

	req := httptest.NewRequest(http.MethodPost, "/customer/register", bytes.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Call the handler
	err := customer_handler.RegisterCustomer(c)

	// Assertions
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		response := map[string]interface{}{}
		json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "Customer John Doe registered successfully")
	}
}

// Test for LoginCustomer
func TestLoginCustomer(t *testing.T) {
	e := echo.New()
	defer teardownDB(config.Pool)

	// Hash password for mock customer
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)

	// Insert mock customer data into the database
	query := `INSERT INTO customers (name, email, password) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING`
	_, err := config.Pool.Exec(context.Background(), query, "John Doe", "john.doe@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to insert mock customer: %v", err)
	}

	// Mock request payload
	requestPayload := map[string]string{
		"email":    "john.doe@example.com",
		"password": "Password123",
	}
	requestBody, _ := json.Marshal(requestPayload)

	req := httptest.NewRequest(http.MethodPost, "/customer/login", bytes.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Call the handler
	err = customer_handler.LoginCustomer(c)

	// Assertions
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		response := map[string]interface{}{}
		json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["token"], "")
		assert.Equal(t, response["email"], "john.doe@example.com")
	}
}