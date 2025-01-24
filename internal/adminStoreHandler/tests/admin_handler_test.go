package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid" // Add this package for UUID generation
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/midtrans/midtrans-go"
	"github.com/midtrans/midtrans-go/coreapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	handler "ftgo-finpro/internal/adminStoreHandler"
	"ftgo-finpro/config/database"
	"fmt"
	"os"
	"time"
)

// MockCoreAPI is a mock implementation of CoreAPIInterface
type MockCoreAPI struct {
	mock.Mock
}

func (m *MockCoreAPI) ChargeTransaction(request *coreapi.ChargeReq) (*coreapi.ChargeResponse, *midtrans.Error) {
	args := m.Called(request)
	return args.Get(0).(*coreapi.ChargeResponse), args.Get(1).(*midtrans.Error)
}

func TestFacilitatePurchase(t *testing.T) {
	e := echo.New()

	// Initialize the mock CoreAPI
	mockCoreAPI := new(MockCoreAPI)
	handler.SetCoreAPI(mockCoreAPI) // Inject the mock implementation

	t.Run("Valid Online Purchase", func(t *testing.T) {
		// Generate valid UUIDs for the store and customer IDs
		storeID := uuid.NewString()
		customerID := uuid.NewString()

		// Insert mock store
		storeProducts := `[{"product": "Product A", "price": 5000, "weight": 1.0, "quantity": 10}]`
		productTypes := `["Electronics"]`
		_, err := config.Pool.Exec(context.Background(),
			`INSERT INTO stores (id, name, products, product_types, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, NOW(), NOW()) ON CONFLICT (id) DO NOTHING`,
			storeID, "Mock Store", storeProducts, productTypes,
		)
		assert.NoError(t, err)

		// Insert mock customer with password
		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO customers (id, name, email, password, wallet_balance, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) ON CONFLICT (id) DO NOTHING`,
			customerID, "Mock Customer", "mock.customer@example.com", "securepassword", 10000,
		)
		assert.NoError(t, err)

		// Mock admin token
		adminContext := &jwt.Token{
			Claims: jwt.MapClaims{
				"store_id": storeID,
			},
		}

		// Mock request data
		requestBody := map[string]interface{}{
			"customer_id":    customerID, // Use the generated `customerID`
			"items":          []map[string]interface{}{{"product": "Product A", "quantity": 2}},
			"payment_method": "Online",
		}

		// Mock response from Midtrans
		mockResponse := &coreapi.ChargeResponse{
			TransactionStatus: "pending",
			VaNumbers: []coreapi.VANumber{
				{Bank: "bca", VANumber: "123456789"},
			},
		}
		mockCoreAPI.On("ChargeTransaction", mock.Anything).Return(mockResponse, nil)

		// Prepare HTTP request
		body, _ := json.Marshal(requestBody)
		req := httptest.NewRequest(http.MethodPost, "/facilitate-purchase", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", adminContext)

		// Call handler
		err = handler.FacilitatePurchase(c)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "Purchase initiated successfully")
	})

	t.Run("Valid Wallet Purchase", func(t *testing.T) {
		// Generate valid UUIDs for the store and customer IDs
		storeID := uuid.NewString()
		customerID := uuid.NewString()
	
		// Generate a unique email for the mock customer
		uniqueEmail := fmt.Sprintf("mock.customer+%s@example.com", uuid.NewString())
	
		// Insert mock store
		storeProducts := `[{"product": "Product A", "price": 5000, "weight": 1.0, "quantity": 10}]`
		productTypes := `["Electronics"]`
		_, err := config.Pool.Exec(context.Background(),
			`INSERT INTO stores (id, name, products, product_types, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, NOW(), NOW()) ON CONFLICT (id) DO NOTHING`,
			storeID, "Mock Store", storeProducts, productTypes,
		)
		assert.NoError(t, err)
	
		// Insert mock customer with a unique email
		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO customers (id, name, email, password, wallet_balance, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) ON CONFLICT (id) DO NOTHING`,
			customerID, "Mock Customer", uniqueEmail, "securepassword", 10000,
		)
		assert.NoError(t, err)
	
		// Mock admin token
		adminContext := &jwt.Token{
			Claims: jwt.MapClaims{
				"store_id": storeID,
			},
		}
	
		// Mock request data
		requestBody := map[string]interface{}{
			"customer_id":    customerID,
			"items":          []map[string]interface{}{{"product": "Product A", "quantity": 2}},
			"payment_method": "Wallet",
		}
	
		// Prepare HTTP request
		body, _ := json.Marshal(requestBody)
		req := httptest.NewRequest(http.MethodPost, "/facilitate-purchase", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", adminContext)
	
		// Call handler
		err = handler.FacilitatePurchase(c)
	
		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "Purchase successful")
		assert.Equal(t, 10000.0, response["total_amount"])
	})
	
}

// problematic test (recycle)

// test redeem token
func TestRedeemToken(t *testing.T) {
	e := echo.New()

	t.Run("Valid Token Redemption", func(t *testing.T) {
		// Setup environment variable for the secret key
		os.Setenv("VENDOR_CUSTOMER_SECRET", "mock-secret-key")

		// Generate valid UUID for customer ID
		customerID := uuid.NewString()

		// Generate a valid token for testing
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"customer_id": customerID,
			"amount":      5000.0,
			"exp":         time.Now().Add(1 * time.Hour).Unix(), // Token expires in 1 hour
		})
		tokenString, _ := token.SignedString([]byte("mock-secret-key"))

		// Insert mock customer
		_, err := config.Pool.Exec(context.Background(),
			`INSERT INTO customers (id, name, email, password, wallet_balance, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) ON CONFLICT (id) DO NOTHING`,
			customerID, "Mock Customer", "mock.customer@example.com", "mockpassword123", 10000.0,
		)
		assert.NoError(t, err)

		// Insert mock token into customer_tokens table
		_, err = config.Pool.Exec(context.Background(),
			`INSERT INTO customer_tokens (id, customer_id, token, issued_at, is_redeemed)
			 VALUES (gen_random_uuid(), $1, $2, NOW(), FALSE)`,
			customerID, tokenString,
		)
		assert.NoError(t, err)

		// Mock request payload
		reqBody := map[string]string{
			"token": tokenString,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/redeem-token/"+customerID, bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("customer_id")
		c.SetParamValues(customerID)

		// Call the handler
		err = handler.RedeemToken(c)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "Token redeemed successfully")
		assert.Equal(t, 5000.0, response["redeemed_amount"])

		// Verify the wallet balance is updated
		var walletBalance float64
		err = config.Pool.QueryRow(context.Background(),
			"SELECT wallet_balance FROM customers WHERE id = $1",
			customerID).Scan(&walletBalance)
		assert.NoError(t, err)
		assert.Equal(t, 15000.0, walletBalance) // Original balance + redeemed amount

		// Verify the token is marked as redeemed
		var isRedeemed bool
		err = config.Pool.QueryRow(context.Background(),
			"SELECT is_redeemed FROM customer_tokens WHERE token = $1",
			tokenString).Scan(&isRedeemed)
		assert.NoError(t, err)
		assert.True(t, isRedeemed)
	})

	t.Run("Invalid Token Redemption - Expired Token", func(t *testing.T) {
		// Generate valid UUID for customer ID
		customerID := uuid.NewString()

		// Generate an expired token
		expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"customer_id": customerID,
			"amount":      5000.0,
			"exp":         time.Now().Add(-1 * time.Hour).Unix(), // Token expired 1 hour ago
		})
		expiredTokenString, _ := expiredToken.SignedString([]byte("mock-secret-key"))

		// Mock request payload
		reqBody := map[string]string{
			"token": expiredTokenString,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/redeem-token/"+customerID, bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("customer_id")
		c.SetParamValues(customerID)

		// Call the handler
		err := handler.RedeemToken(c)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var response map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Contains(t, response["message"], "Invalid or expired token")
	})
}