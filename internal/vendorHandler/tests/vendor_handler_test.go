package tests

import (
	"bytes"
	"encoding/json"
	"ftgo-finpro/internal/vendorHandler"
	"net/http"
	"net/http/httptest"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/labstack/echo/v4"
	cust_middleware "ftgo-finpro/internal/middleware"
	"github.com/google/uuid"

	"ftgo-finpro/config/database"
	"golang.org/x/crypto/bcrypt"
	"context"
	"github.com/golang-jwt/jwt/v4"
	"time"
	"fmt"
)

var jwtSecret = "vendor_customer_secret_key"

func TestVendorHandler(t *testing.T) {
	e := echo.New()

	// Configure JWT middleware for tests
	e.Use(cust_middleware.JWTMiddleware)

	t.Run("RegisterVendorAdmin - Valid Registration", func(t *testing.T) {
		// Retrieve an existing vendor ID from the database
		var validVendorID string
		err := config.Pool.QueryRow(context.Background(),
			`SELECT id FROM vendors LIMIT 1`).Scan(&validVendorID)
		assert.NoError(t, err)
		assert.NotEmpty(t, validVendorID, "Vendor ID should not be empty")
	
		// Setup request
		reqBody := map[string]interface{}{
			"name":       "John Doe",
			"email":      "johndoe@example.com",
			"password":   "strongpassword",
			"vendor_id":  validVendorID, // Use the valid vendor ID from the database
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/register-vendor-admin", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
	
		// Call the handler
		err = handler.RegisterVendorAdmin(c)
	
		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "registered successfully")
	})
	

	t.Run("LoginVendorAdmin - Invalid Password", func(t *testing.T) {
		// Insert a mock vendor admin
		vendorID := uuid.NewString()
		email := "johndoe@example.com"
		password := "strongpassword"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		_, _ = config.Pool.Exec(context.Background(),
			`INSERT INTO vendor_admins (id, name, email, password, vendor_id) VALUES ($1, $2, $3, $4, $5)`,
			uuid.NewString(), "Admin Name", email, hashedPassword, vendorID)
	
		// Attempt login with invalid password
		reqBody := map[string]interface{}{
			"email":    email,
			"password": "wrongpassword",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/login-vendor-admin", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
	
		// Call the handler
		err := handler.LoginVendorAdmin(c)
	
		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var response map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Equal(t, response["message"], "Invalid email or password")
	})
	
	t.Run("FacilitateCustomerRecycle - Invalid Material Type", func(t *testing.T) {
		// Fetch valid vendor ID and customer ID from the database
		var vendorID, customerID string
		err := config.Pool.QueryRow(context.Background(), `SELECT id FROM vendors LIMIT 1`).Scan(&vendorID)
		assert.NoError(t, err)
		assert.NotEmpty(t, vendorID, "Vendor ID should not be empty")
		
		err = config.Pool.QueryRow(context.Background(), `SELECT id FROM customers LIMIT 1`).Scan(&customerID)
		assert.NoError(t, err)
		assert.NotEmpty(t, customerID, "Customer ID should not be empty")
	
		// Insert a mock transaction with valid IDs
		transactionID := uuid.NewString()
		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO vending_transactions (id, customer_id, vendor_id, materials, is_processed)
			 VALUES ($1, $2, $3, $4, $5)`,
			transactionID, customerID, vendorID, `[{"type": "INVALID", "weight": 2.0}]`, false)
		assert.NoError(t, err)
	
		// Mock JWT token with the correct vendor_id
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"vendor_id": vendorID,
			"exp":       jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		})
		tokenString, err := token.SignedString([]byte(jwtSecret))
		assert.NoError(t, err)
	
		// Mock request
		req := httptest.NewRequest(http.MethodPost, "/facilitate-recycle/"+transactionID, nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("transaction_id")
		c.SetParamValues(transactionID)
		c.Set("user", token) // Simulate middleware
	
		// Call the handler
		err = handler.FacilitateCustomerRecycle(c)
	
		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var response map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "Material type 'INVALID' not recognized")
	})
	
	t.Run("GetVendingMachineStatus - Valid Vending Machine", func(t *testing.T) {
		// Insert mock vending machine
		vendingMachineID := uuid.NewString()
		_, err := config.Pool.Exec(context.Background(),
			`INSERT INTO vending_machines (id, type, weight_limit, current_weight, current_fill, compatible_plastics) 
			 VALUES ($1, 'Plastic', 100.0, 50.0, 10, '["PET", "HDPE"]')`,
			vendingMachineID)
		assert.NoError(t, err)

		// Mock request
		req := httptest.NewRequest(http.MethodGet, "/vending-machine/"+vendingMachineID+"/status", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("vending_machine_id")
		c.SetParamValues(vendingMachineID)

		// Call the handler
		err = handler.GetVendingMachineStatus(c)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Equal(t, vendingMachineID, response["vending_machine_id"])
		assert.Equal(t, 100.0, response["weight_limit"])
		assert.Equal(t, 50.0, response["current_weight"])
		assert.Equal(t, 10, int(response["current_fill"].(float64)))
		assert.Equal(t, false, response["is_full"])
		assert.ElementsMatch(t, response["compatible_plastics"], []interface{}{"PET", "HDPE"})
	})

	t.Run("RequestPickup - Full Vending Machine", func(t *testing.T) {
		// Insert mock vendor and vending machine
		vendorID := uuid.NewString()
		vendingMachineID := uuid.NewString()
		_, err := config.Pool.Exec(context.Background(),
			`INSERT INTO vendors (id, name, email, password) VALUES ($1, 'Test Vendor', 'test@vendor.com', 'password')`,
			vendorID)
		assert.NoError(t, err)

		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO vending_machines (id, vendor_id, type, weight_limit, current_weight, compatible_plastics) 
			 VALUES ($1, $2, 'Plastic', 100.0, 100.0, '["PET", "HDPE"]')`,
			vendingMachineID, vendorID)
		assert.NoError(t, err)

		// Mock JWT token with the correct vendor ID
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"vendor_id": vendorID,
			"exp":       jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		})
		tokenString, err := token.SignedString([]byte(jwtSecret))
		assert.NoError(t, err)

		// Mock request
		req := httptest.NewRequest(http.MethodPost, "/request-pickup/"+vendingMachineID, nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("vending_machine_id")
		c.SetParamValues(vendingMachineID)
		c.Set("user", token) // Simulate middleware

		// Call the handler
		err = handler.RequestPickup(c)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Equal(t, "Pickup requested successfully", response["message"])
	})

	t.Run("RequestPickup - Vending Machine Not Full", func(t *testing.T) {
		// Generate unique IDs and email
		vendorID := uuid.NewString()
		vendingMachineID := uuid.NewString()
		email := fmt.Sprintf("vendor_%s@example.com", uuid.NewString())
	
		// Insert mock vendor with unique email
		_, err := config.Pool.Exec(context.Background(),
			`INSERT INTO vendors (id, name, email, password) VALUES ($1, 'Test Vendor', $2, 'password')`,
			vendorID, email)
		assert.NoError(t, err)
	
		// Insert vending machine with a weight below the limit
		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO vending_machines (id, vendor_id, type, weight_limit, current_weight, compatible_plastics) 
			 VALUES ($1, $2, 'Plastic', 100.0, 50.0, '["PET", "HDPE"]')`,
			vendingMachineID, vendorID)
		assert.NoError(t, err)
	
		// Mock JWT token with the correct vendor_id
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"vendor_id": vendorID,
			"exp":       jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		})
		tokenString, err := token.SignedString([]byte(jwtSecret))
		assert.NoError(t, err)
	
		// Mock request
		req := httptest.NewRequest(http.MethodPost, "/request-pickup/"+vendingMachineID, nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("vending_machine_id")
		c.SetParamValues(vendingMachineID)
		c.Set("user", token) // Simulate middleware
	
		// Call the handler
		err = handler.RequestPickup(c)
	
		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var response map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Equal(t, "Vending machine is not full", response["message"])
	})
	
}