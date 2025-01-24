package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	config "ftgo-finpro/config/database"
	admin_handler "ftgo-finpro/internal/adminStoreHandler"
	"fmt"
)

func teardownDBForVerifyCustomer(email string) {
	// Clean up the customer created for the test
	_, err := config.Pool.Exec(context.Background(), "DELETE FROM customers WHERE email = $1", email)
	if err != nil {
		panic(err)
	}
}

type MockUtils struct {
	mock.Mock
}

var Utils interface {

    SendEmailVerifNotification(email string) error

}

func (m *MockUtils) SendEmailVerifNotification(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func TestVerifyCustomer(t *testing.T) {
	e := echo.New()

	// Mock email
	customerEmail := "customer.test@example.com"

	// Mock customer data with a dummy password
	defer teardownDBForVerifyCustomer(customerEmail)
	_, err := config.Pool.Exec(context.Background(), `
		INSERT INTO customers (id, name, email, password, is_verified)
		VALUES (gen_random_uuid(), 'Test Customer', $1, $2, FALSE)
	`, customerEmail, "hashedpassword123") // Dummy hashed password
	if err != nil {
		t.Fatalf("Failed to insert mock customer: %v", err)
	}

	mockSendEmail := func(email string) error {
		if email != customerEmail {
			return fmt.Errorf("Unexpected email: %s", email)
		}
		return nil
	}

	// Define test cases
	testCases := []struct {
		name         string
		requestBody  map[string]string
		setupFunc    func()
		expectedCode int
		expectedMsg  string
	}{
		{
			name: "Valid Verification",
			requestBody: map[string]string{
				"email": customerEmail,
			},
			setupFunc:    func() {},
			expectedCode: http.StatusOK,
			expectedMsg:  "Customer verified successfully",
		},
		{
			name: "Already Verified Customer",
			requestBody: map[string]string{
				"email": customerEmail,
			},
			setupFunc: func() {
				_, err := config.Pool.Exec(context.Background(), `
					UPDATE customers SET is_verified = TRUE WHERE email = $1
				`, customerEmail)
				if err != nil {
					t.Fatalf("Failed to update customer verification status: %v", err)
				}
			},
			expectedCode: http.StatusBadRequest,
			expectedMsg:  "Customer already verified",
		},
		{
			name: "Customer Not Found",
			requestBody: map[string]string{
				"email": "nonexistent@example.com",
			},
			setupFunc:    func() {},
			expectedCode: http.StatusNotFound,
			expectedMsg:  "Customer not found",
		},
		{
			name: "Invalid Email Format",
			requestBody: map[string]string{
				"email": "invalidemail",
			},
			setupFunc:    func() {},
			expectedCode: http.StatusBadRequest,
			expectedMsg:  "Invalid email format",
		},
		{
			name: "Empty Email Field",
			requestBody: map[string]string{
				"email": "",
			},
			setupFunc:    func() {},
			expectedCode: http.StatusBadRequest,
			expectedMsg:  "Invalid email",
		},
	}

	// Execute test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Run the setup function for the test case
			tc.setupFunc()

			// Create the request
			requestBody, _ := json.Marshal(tc.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/verify/customer", bytes.NewReader(requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Call the handler with the mock email function
			err := admin_handler.VerifyCustomer(c, mockSendEmail)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedCode, rec.Code)

			// Check the response message
			response := map[string]string{}
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["message"], tc.expectedMsg)
		})
	}
}
