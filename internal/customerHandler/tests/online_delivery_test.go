package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	config "ftgo-finpro/config/database"
	customer_handler "ftgo-finpro/internal/customerHandler"
)

// Cleanup database after tests
func teardownDBForOnlineDelivery(storeID, customerID string) {
	queries := []string{
		"DELETE FROM customer_transactions WHERE customer_id = $1",
		"DELETE FROM store_transactions WHERE store_id = $1",
		"DELETE FROM customers WHERE id = $1",
		"DELETE FROM stores WHERE id = $1",
	}

	for _, query := range queries {
		if _, err := config.Pool.Exec(context.Background(), query, storeID); err != nil {
			panic(err)
		}
		if _, err := config.Pool.Exec(context.Background(), query, customerID); err != nil {
			panic(err)
		}
	}
}

// Test cases for FacilitatePurchaseOnline
func TestFacilitatePurchaseOnline(t *testing.T) {
	e := echo.New()

	// Set up test data
	storeID := uuid.New().String()
	customerID := uuid.New().String()
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"store_id": storeID,
	})

	// Clean up after tests
	defer teardownDBForOnlineDelivery(storeID, customerID)

	// Mock admin JWT token
	adminContext := e.NewContext(nil, nil)
	adminContext.Set("user", adminToken)

	// Insert mock store and customer data
	storeQuery := `INSERT INTO stores (id, name, products, product_types) VALUES ($1, $2, $3, $4)`
	storeProducts := `[{"product": "Product A", "price": 10000, "quantity": 50, "weight": 1.5}, {"product": "Product B", "price": 15000, "quantity": 30, "weight": 2.0}]`
	productTypes := `["Type A", "Type B"]`
	_, err := config.Pool.Exec(context.Background(), storeQuery, storeID, "Test Store", storeProducts, productTypes)
	if err != nil {
		t.Fatalf("Failed to insert mock store: %v", err)
	}

	hashedPassword := "hashedPassword123" // Replace with actual hash logic if needed
	customerQuery := `INSERT INTO customers (id, name, email, password, wallet_balance) VALUES ($1, $2, $3, $4, $5)`
	_, err = config.Pool.Exec(context.Background(), customerQuery, customerID, "John Doe", "john.doe@example.com", hashedPassword, 50000.0)
	if err != nil {
		t.Fatalf("Failed to insert mock customer: %v", err)
	}

	// Define test cases
	testCases := []struct {
		name         string
		purchaseData map[string]interface{}
		expectedCode int
		expectedMsg  string
	}{
		{
			name: "Valid Purchase with Wallet",
			purchaseData: map[string]interface{}{
				"customer_id": customerID,
				"items": []map[string]interface{}{
					{"product": "Product A", "quantity": 2},
					{"product": "Product B", "quantity": 1},
				},
				"payment_method": "Wallet",
				"origin":        "-6.200000,106.816666",
				"destination":   "-6.121435,106.774124",
			},
			expectedCode: http.StatusOK,
			expectedMsg:  "Purchase successful",
		},
		{
			name: "Insufficient Wallet Balance",
			purchaseData: map[string]interface{}{
				"customer_id": customerID,
				"items": []map[string]interface{}{
					{"product": "Product A", "quantity": 2}, // Valid quantity within stock
				},
				"payment_method": "Wallet",
				"origin":        "-6.200000,106.816666",
				"destination":   "-6.121435,106.774124",
			},
			expectedCode: http.StatusBadRequest,
			expectedMsg:  "Insufficient wallet balance",
		},
		{
			name: "Invalid Product",
			purchaseData: map[string]interface{}{
				"customer_id": customerID,
				"items": []map[string]interface{}{
					{"product": "Invalid Product", "quantity": 2},
				},
				"payment_method": "Wallet",
				"origin":        "-6.200000,106.816666",
				"destination":   "-6.121435,106.774124",
			},
			expectedCode: http.StatusBadRequest,
			expectedMsg:  "Invalid product",
		},
	}

	// Execute test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestBody, _ := json.Marshal(tc.purchaseData)
			req := httptest.NewRequest(http.MethodPost, "/purchase/online", bytes.NewReader(requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Set admin token in context
			c.Set("user", adminToken)

			// Call the handler
			err = customer_handler.FacilitatePurchaseOnline(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedCode, rec.Code)

			// Check response
			response := map[string]interface{}{}
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["message"], tc.expectedMsg)
		})
	}
}