package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"github.com/google/uuid"	

	config "ftgo-finpro/config/database"
	customer_handler "ftgo-finpro/internal/customerHandler"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// Cleanup database after tests
func teardownDBForCustomerHandlers(customerID string) {
	if customerID == "" {
		return
	}

	// Delete from customer_tokens
	tokenQuery := "DELETE FROM customer_tokens WHERE customer_id = $1"
	_, err := config.Pool.Exec(context.Background(), tokenQuery, customerID)
	if err != nil {
		panic(err)
	}

	// Delete from customer_transactions
	transactionQuery := "DELETE FROM customer_transactions WHERE customer_id = $1"
	_, err = config.Pool.Exec(context.Background(), transactionQuery, customerID)
	if err != nil {
		panic(err)
	}

	// Delete from customers
	customerQuery := "DELETE FROM customers WHERE id = $1"
	_, err = config.Pool.Exec(context.Background(), customerQuery, customerID)
	if err != nil {
		panic(err)
	}

	// Delete from store_coordinates (optional if related data exists)
	storeQuery := "DELETE FROM store_coordinates WHERE store_name = $1"
	_, err = config.Pool.Exec(context.Background(), storeQuery, "Mock Store")
	if err != nil {
		panic(err)
	}
}


// Test for `GetWalletBalance`
func TestGetWalletBalance(t *testing.T) {
	config.InitDB() // Reinitialize the database connection
	e := echo.New()

	// Generate a valid UUID for the customer
	customerID := uuid.New().String()

	// Ensure data is cleaned up after the test
	defer teardownDBForCustomerHandlers(customerID)

	// Hash a dummy password for the mock customer
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)

	// Insert mock customer data with wallet balance
	query := `INSERT INTO customers (id, name, email, password, wallet_balance) VALUES ($1, $2, $3, $4, $5)`
	_, err := config.Pool.Exec(context.Background(), query, customerID, "John Doe", "john.doe@example.com", string(hashedPassword), 1000.0)
	if err != nil {
		t.Fatalf("Failed to insert mock customer: %v", err)
	}

	// Mock JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"customer_id": customerID,
	})
	c := e.NewContext(nil, nil)
	c.Set("user", token)

	// Mock request and response
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/customer/wallet", nil)
	c.SetRequest(req)
	c.Response().Writer = rec

	// Call the handler
	err = customer_handler.GetWalletBalance(c)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		response := map[string]interface{}{}
		json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Equal(t, 1000.0, response["wallet_balance"])
	}
}

// Test for `WithdrawMoney`
func TestWithdrawMoney(t *testing.T) {
	config.InitDB()
	e := echo.New()

	// Generate a valid UUID for the customer
	customerID := uuid.New().String()

	// Ensure data is cleaned up after the test
	defer teardownDBForCustomerHandlers(customerID)

	// Hash a dummy password for the mock customer
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)

	// Insert mock customer data
	query := `INSERT INTO customers (id, name, email, password, wallet_balance) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING`
	_, err := config.Pool.Exec(context.Background(), query, customerID, "John Doe", "john.doe@example.com", string(hashedPassword), 1000.0)
	if err != nil {
		t.Fatalf("Failed to insert mock customer: %v", err)
	}

	// Mock JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"customer_id": customerID,
		"name":        "John Doe",
	})
	c := e.NewContext(nil, nil)
	c.Set("user", token)

	// Mock request payload
	requestPayload := map[string]interface{}{
		"amount": 500.0,
	}
	requestBody, _ := json.Marshal(requestPayload)
	req := httptest.NewRequest(http.MethodPost, "/customer/withdraw", bytes.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Mock response
	rec := httptest.NewRecorder()
	c.SetRequest(req)
	c.Response().Writer = rec

	// Call the handler
	err = customer_handler.WithdrawMoney(c)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		response := map[string]interface{}{}
		json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "Withdrawal initiated successfully")
		assert.Equal(t, "pending", response["status"])
	}
}

// Test for `GetCustomerTokens`
func TestGetCustomerTokens(t *testing.T) {
	config.InitDB()
	e := echo.New()

	// Generate valid UUIDs for the customer, token, and vendor
	customerID := uuid.New().String()
	tokenID := uuid.New().String()

	// Fetch an existing vendor ID from the `vendors` table
	var vendorID string
	err := config.Pool.QueryRow(context.Background(), "SELECT id FROM vendors LIMIT 1").Scan(&vendorID)
	if err != nil {
		t.Fatalf("Failed to fetch a vendor ID: %v", err)
	}

	// Ensure data is cleaned up after the test
	defer teardownDBForCustomerHandlers(customerID)

	// Hash a dummy password for the mock customer
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)

	// Insert mock customer and tokens
	customerQuery := `INSERT INTO customers (id, name, email, password) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`
	tokenQuery := `
		INSERT INTO customer_tokens (id, customer_id, vendor_id, token, issued_at, is_redeemed)
		VALUES ($1, $2, $3, $4, NOW(), FALSE)
	`
	_, err = config.Pool.Exec(context.Background(), customerQuery, customerID, "John Doe", "john.doe@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to insert mock customer: %v", err)
	}
	_, err = config.Pool.Exec(context.Background(), tokenQuery, tokenID, customerID, vendorID, "mock_token")
	if err != nil {
		t.Fatalf("Failed to insert mock token: %v", err)
	}

	// Mock JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"customer_id": customerID,
	})
	c := e.NewContext(nil, nil)
	c.Set("user", token)

	// Mock request and response
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/customer/tokens", nil)
	c.SetRequest(req)
	c.Response().Writer = rec

	// Call the handler
	err = customer_handler.GetCustomerTokens(c)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		response := map[string]interface{}{}
		json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Equal(t, "Customer tokens fetched successfully", response["message"])
		assert.NotEmpty(t, response["tokens"])
	}
}

// Test for `GetAllStoreCoordinate`
func TestGetAllStoreCoordinate(t *testing.T) {
	config.InitDB()
	e := echo.New()

	// Generate a valid UUID for the customer (even if unused here)
	customerID := uuid.New().String()

	// Ensure data is cleaned up after the test
	defer teardownDBForCustomerHandlers(customerID)

	// Insert mock store data
	query := `INSERT INTO store_coordinates (store_name, coordinate) VALUES ($1, $2)`
	_, err := config.Pool.Exec(context.Background(), query, "Mock Store", "123.456,789.123")
	if err != nil {
		t.Fatalf("Failed to insert mock store: %v", err)
	}

	// Mock request and response
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/store/coordinates", nil)
	c := e.NewContext(req, rec)

	// Call the handler
	err = customer_handler.GetAllStoreCoordinate(c)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		response := map[string]interface{}{}
		json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Equal(t, "We found the store locations for you!", response["message"])
		assert.NotEmpty(t, response["stores"])
	}
}