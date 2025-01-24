package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"ftgo-finpro/config/database"
	factoryHandler "ftgo-finpro/internal/factoryHandler"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"github.com/labstack/echo/v4"
	cust_middleware "ftgo-finpro/internal/middleware"
)

var jwtSecret = "Secret_Key"

func TestFactoryHandler(t *testing.T) {
	e := echo.New()

	// Configure JWT middleware for tests
	e.Use(cust_middleware.JWTMiddleware)

	t.Run("RegisterFactoryAdmin", func(t *testing.T) {
		// Use an existing factory from the database
		var factoryID string
		err := config.Pool.QueryRow(context.Background(),
			`SELECT id FROM factories LIMIT 1`).Scan(&factoryID)
		assert.NoError(t, err)
		assert.NotEmpty(t, factoryID, "Factory ID should not be empty")

		// Generate unique email for the factory admin
		email := "admin_" + uuid.NewString() + "@example.com"

		// Register factory admin
		reqBody := map[string]interface{}{
			"name":       "Johny Sins",
			"email":      email,
			"password":   "johnys1ns",
			"factory_id": factoryID,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/register-factory-admin", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Call handler
		err = factoryHandler.RegisterFactoryAdmin(c)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "registered successfully")
	})

	t.Run("LoginFactoryAdmin", func(t *testing.T) {
		// Generate unique email for login test
		email := "admin_login_" + uuid.NewString() + "@example.com"
		password := "securepassword"

		// Use an existing factory from the database
		var factoryID string
		err := config.Pool.QueryRow(context.Background(),
			`SELECT id FROM factories LIMIT 1`).Scan(&factoryID)
		assert.NoError(t, err)

		// Hash the password
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		// Insert factory admin into the database
		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO factory_admins (id, name, email, password, factory_id, created_at)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW())`,
			"Johny Sins", email, string(hashedPassword), factoryID,
		)
		assert.NoError(t, err)

		// Attempt valid login
		reqBody := map[string]interface{}{
			"email":    email,
			"password": password,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/login-factory-admin", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Call handler
		err = factoryHandler.LoginFactoryAdmin(c)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response, "token")
	})

	t.Run("ProcessFactoryRequest", func(t *testing.T) {
		factoryID := uuid.NewString()
		vendorID := uuid.NewString()
		vendingMachineID := uuid.NewString()
		requestID := uuid.NewString()
	
		// Insert mock factory
		_, err := config.Pool.Exec(context.Background(),
			`INSERT INTO factories (id, name, location, created_at)
			 VALUES ($1, $2, $3, NOW())`,
			factoryID, "Test Factory", "Test Location",
		)
		assert.NoError(t, err)
	
		// Insert mock vendor
		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO vendors (id, name, email, password, revenue, created_at)
			 VALUES ($1, $2, $3, $4, $5, NOW())`,
			vendorID, "Test Vendor", "vendor@example.com", "vendorpass", 0.0,
		)
		assert.NoError(t, err)
	
		// Insert mock vending machine
		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO vending_machines (id, store_id, vendor_id, weight_limit, current_weight, compatible_plastics, created_at)
			 VALUES ($1, (SELECT id FROM stores LIMIT 1), $2, $3, $4, $5, NOW())`,
			vendingMachineID, vendorID, 100.0, 50.0, `["PET"]`, // Added weight_limit = 100.0
		)
		assert.NoError(t, err)
	
		// Insert mock factory vendor request
		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO factory_vendor_requests (id, factory_id, vendor_id, vending_machine_id, status, created_at)
			 VALUES ($1, $2, $3, $4, 'Pending', NOW())`,
			requestID, factoryID, vendorID, vendingMachineID,
		)
		assert.NoError(t, err)
	
		// Generate a mock JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"factory_id": factoryID,
			"exp":        jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		})
		tokenString, _ := token.SignedString([]byte(jwtSecret))
	
		// Mock the request
		req := httptest.NewRequest(http.MethodPost, "/process-request/"+requestID, nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("request_id")
		c.SetParamValues(requestID)
	
		// Manually set the "user" value to simulate middleware behavior
		c.Set("user", token)
	
		// Call the handler
		err = factoryHandler.ProcessFactoryRequest(c)
	
		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "Request processed successfully")
		assert.Equal(t, vendorID, response["vendor_id"])
	})		
}
