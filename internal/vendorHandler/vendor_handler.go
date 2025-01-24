package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"ftgo-finpro/utils"
	"net/http"
	"os"
	"strings"
	"time"

	config "ftgo-finpro/config/database"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgconn"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

// VendorAdmin struct
type VendorAdmin struct {
	ID        string `json:"id"`
	VendorID  string `json:"vendor_id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	JwtToken  string `json:"jwt_token"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// RegisterVendorAdminRequest struct
type RegisterVendorAdminRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	VendorID string `json:"vendor_id" validate:"required"`
}

// transaction struct to view vending_transactions
type Transaction struct {
	ID            string    `json:"id"`
	CustomerID    string    `json:"customer_id"`
	StoreAdminID  string    `json:"store_admin_id"`
	VendorID      string    `json:"vendor_id"`
	Materials     string    `json:"materials"`       // Assuming JSONB will be stored as a JSON string
	NumberOfItems int       `json:"number_of_items"` // Integer field
	IsProcessed   bool      `json:"is_processed"`    // Boolean field
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// LoginVendorAdminRequest struct
type LoginVendorAdminRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginVendorAdminResponse struct
type LoginVendorAdminResponse struct {
	Token string `json:"token"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

var jwtSecret = os.Getenv("JWT_SECRET")

// RegisterVendorAdmin godoc
// @Summary Register a vendor admin
// @Description Registers a new vendor admin with name, email, password, and vendor ID.
// @Tags Vendor Admin
// @Accept json
// @Produce json
// @Param body body handler.RegisterVendorAdminRequest true "Vendor Admin Registration Request"
// @Success 200 {object} map[string]interface{} "Vendor admin registered successfully"
// @Failure 400 {object} map[string]string "Invalid request or email already registered"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /vendor-admin/register [post]
func RegisterVendorAdmin(c echo.Context) error {
	var req RegisterVendorAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	if req.Name == "" || req.Email == "" || req.Password == "" || req.VendorID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "All fields are required"})
	}

	// Validate email format
	if !utils.ValidateEmail(req.Email) {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email format"})
	}

	email := strings.ToLower(req.Email)

	// Validate password strength (e.g., min 8 chars)
	if len(req.Password) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Password must be at least 8 characters long"})
	}

	// Hash the password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	// Insert into vendor_admins table
	adminQuery := `
		INSERT INTO vendor_admins (name, email, password, vendor_id) 
		VALUES ($1, $2, $3, $4) RETURNING id`
	var adminID string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = config.Pool.QueryRow(ctx, adminQuery, req.Name, email, string(hashPassword), req.VendorID).Scan(&adminID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Email already registered"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Vendor admin %s registered successfully", req.Name),
		"email":   email,
	})
}

// LoginVendorAdmin godoc
// @Summary Login for vendor admin
// @Description Authenticates a vendor admin using email and password, returning a JWT token.
// @Tags Vendor Admin
// @Accept json
// @Produce json
// @Param body body handler.LoginVendorAdminRequest true "Vendor Admin Login Request"
// @Success 200 {object} handler.LoginVendorAdminResponse "Login successful with token"
// @Failure 400 {object} map[string]string "Invalid email or password"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /vendor-admin/login [post]
func LoginVendorAdmin(c echo.Context) error {
	var req LoginVendorAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Convert email to lowercase for case-insensitive comparison
	req.Email = strings.ToLower(req.Email)

	// Fetch admin details
	var admin VendorAdmin
	query := `
		SELECT id, vendor_id, name, email, password 
		FROM vendor_admins 
		WHERE email = $1`
	err := config.Pool.QueryRow(context.Background(), query, req.Email).Scan(
		&admin.ID, &admin.VendorID, &admin.Name, &admin.Email, &admin.Password,
	)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(req.Password)); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"admin_id":  admin.ID,
		"name":      admin.Name,
		"email":     admin.Email,
		"vendor_id": admin.VendorID,
		"exp":       jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
	})
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate token"})
	}

	// Update the JWT token in the database
	updateQuery := `UPDATE vendor_admins SET jwt_token = $1 WHERE id = $2`
	if _, err := config.Pool.Exec(context.Background(), updateQuery, tokenString, admin.ID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update token"})
	}

	// Return login response
	return c.JSON(http.StatusOK, LoginVendorAdminResponse{
		Token: tokenString,
		Name:  admin.Name,
		Email: admin.Email,
	})
}

// GetTransactions godoc
// @Summary Get transactions for a vendor
// @Description Retrieves all transactions associated with the authenticated vendor.
// @Tags Vendor Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Transactions fetched successfully"
// @Failure 401 {object} map[string]string "Unauthorized access"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /vendor-admin/transactions [get]
func GetTransactions(c echo.Context) error {
	// Extract the JWT token claims
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	vendorID, ok := claims["vendor_id"].(string)
	if !ok || vendorID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"message": "Unauthorized: Missing or invalid vendor ID in token",
		})
	}

	// Query the vending_transactions table for the vendor's transactions
	query := `
		SELECT id, customer_id, store_admin_id, vendor_id, materials, number_of_items, is_processed, created_at, updated_at
		FROM vending_transactions
		WHERE vendor_id = $1
	`
	rows, err := config.Pool.Query(context.Background(), query, vendorID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"message": "Failed to fetch transactions",
		})
	}
	defer rows.Close()

	// Collect the results into a slice of transactions
	var transactions []Transaction
	for rows.Next() {
		var transaction Transaction
		err := rows.Scan(
			&transaction.ID,
			&transaction.CustomerID,
			&transaction.StoreAdminID,
			&transaction.VendorID,
			&transaction.Materials,
			&transaction.NumberOfItems,
			&transaction.IsProcessed,
			&transaction.CreatedAt,
			&transaction.UpdatedAt,
		)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"message": "Failed to parse transactions",
			})
		}
		transactions = append(transactions, transaction)
	}

	// Return the transactions in JSON format
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":      "Transactions fetched successfully",
		"transactions": transactions,
	})
}

// facilitate customer token generation
func GenerateToken(customerID, vendorID string, amount float64) (string, error) {
	claims := jwt.MapClaims{
		"customer_id": customerID,
		"vendor_id":   vendorID,
		"amount":      amount,
		"issued_at":   time.Now().Unix(),
	}	
	
	// derive vendor customer secret from .env
	var vendorCustomerSecret =  os.Getenv("VENDOR_CUSTOMER_SECRET")

	// Ensure the secret key is not empty
	if vendorCustomerSecret == "" {
		return "", fmt.Errorf("VENDOR_CUSTOMER_SECRET is not set in the environment")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(vendorCustomerSecret))
}

// FacilitateCustomerRecycle godoc
// @Summary Facilitate customer recycling
// @Description Processes a customer recycling transaction, calculates rewards, and generates a token.
// @Tags Vendor Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param transaction_id path string true "Transaction ID"
// @Success 200 {object} map[string]interface{} "Recycling facilitated successfully"
// @Failure 400 {object} map[string]string "Invalid or unauthorized transaction"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /vendor-admin/recycle/{transaction_id} [post]
func FacilitateCustomerRecycle(c echo.Context) error {
	// Authenticate and extract vendor admin claims
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	vendorID, ok := claims["vendor_id"].(string)
	if !ok || vendorID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Unauthorized: Invalid vendor ID"})
	}

	// Get transaction ID from URL parameters
	transactionID := c.Param("transaction_id")
	if transactionID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Transaction ID is required"})
	}

	// Fetch the transaction details
	var transaction Transaction
	query := `
        SELECT id, customer_id, vendor_id, materials, number_of_items, is_processed
        FROM vending_transactions
        WHERE id = $1 AND vendor_id = $2
    `
	err := config.Pool.QueryRow(context.Background(), query, transactionID, vendorID).Scan(
		&transaction.ID,
		&transaction.CustomerID,
		&transaction.VendorID,
		&transaction.Materials,
		&transaction.NumberOfItems,
		&transaction.IsProcessed,
	)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid or unauthorized transaction"})
	}

	// Check if the transaction is already processed
	if transaction.IsProcessed {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Transaction already processed"})
	}

	// Parse materials from the transaction
	var materials []struct {
		Type     string  `json:"type"`
		Weight   float64 `json:"weight"`
		Product  string  `json:"product"`
		Quantity int     `json:"quantity"`
	}
	if err := json.Unmarshal([]byte(transaction.Materials), &materials); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse transaction materials"})
	}

	// Fetch pricing details
	pricingQuery := `SELECT type, price_per_kg_customer FROM plastics_pricing`
	rows, err := config.Pool.Query(context.Background(), pricingQuery)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch plastics pricing"})
	}
	defer rows.Close()

	pricing := make(map[string]float64)
	for rows.Next() {
		var materialType string
		var pricePerKg float64
		if err := rows.Scan(&materialType, &pricePerKg); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse pricing data"})
		}
		pricing[materialType] = pricePerKg
	}

	// Calculate total amount for the materials
	totalAmount := 0.0
	for _, material := range materials {
		price, exists := pricing[material.Type]
		if !exists {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"message": fmt.Sprintf("Material type '%s' not recognized", material.Type),
			})
		}
		totalAmount += material.Weight * price
	}

	// Generate a token for the customer
	token, err := GenerateToken(transaction.CustomerID, vendorID, totalAmount)
	if err != nil {
		fmt.Println(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate token"})
	}

	// Store the token in the customer_tokens table
	insertTokenQuery := `
        INSERT INTO customer_tokens (customer_id, vendor_id, token, issued_at)
        VALUES ($1, $2, $3, NOW())
    `
	_, err = config.Pool.Exec(context.Background(), insertTokenQuery, transaction.CustomerID, vendorID, token)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to store token"})
	}

	// Log the transaction in the vendor_customer_report table
	reportData := map[string]interface{}{
		"transaction_id": transactionID,
		"materials":      materials,
		"total_amount":   totalAmount,
	}
	reportDataJSON, _ := json.Marshal(reportData)

	insertReportQuery := `
        INSERT INTO vendor_customer_report (vending_machine_id, vendor_id, report_data, created_at)
        VALUES ((SELECT vending_machine_id FROM vending_transactions WHERE id = $1), $2, $3, NOW())
    `
	_, err = config.Pool.Exec(context.Background(), insertReportQuery, transactionID, vendorID, reportDataJSON)
	if err != nil {
		fmt.Println("error: ", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to log customer report"})
	}

	// Mark the transaction as processed
	updateTransactionQuery := `
        UPDATE vending_transactions SET is_processed = TRUE WHERE id = $1
    `
	_, err = config.Pool.Exec(context.Background(), updateTransactionQuery, transactionID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update transaction status"})
	}

	// Return success response
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":   "Recycling facilitated successfully",
		"token":     token,
		"amount":    totalAmount,
		"materials": materials,
	})
}

// GetVendingMachineStatus godoc
// @Summary Get vending machine status
// @Description Retrieves the status of a specific vending machine.
// @Tags Vendor Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param vending_machine_id path string true "Vending Machine ID"
// @Success 200 {object} map[string]interface{} "Vending machine status retrieved successfully"
// @Failure 400 {object} map[string]string "Invalid vending machine ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /vendor-admin/vending-machine/{vending_machine_id}/status [get]
func GetVendingMachineStatus(c echo.Context) error {
	// Extract vending machine ID from the URL
	vendingMachineID := c.Param("vending_machine_id")
	if vendingMachineID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Vending machine ID is required"})
	}

	// Query the vending machine status
	var weightLimit, currentWeight float64
	var currentFill int
	var compatiblePlastics []string
	query := `
		SELECT weight_limit, current_weight, current_fill, compatible_plastics
		FROM vending_machines WHERE id = $1
	`
	var plasticsJSON []byte
	err := config.Pool.QueryRow(context.Background(), query, vendingMachineID).Scan(&weightLimit, &currentWeight, &currentFill, &plasticsJSON)
	if err != nil {
		fmt.Println("error: ", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch vending machine status"})
	}

	// Parse the JSONB column into a Go slice
	if err := json.Unmarshal(plasticsJSON, &compatiblePlastics); err != nil {
		fmt.Println("error: ", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse compatible plastics"})
	}

	// Return the status
	return c.JSON(http.StatusOK, map[string]interface{}{
		"vending_machine_id":  vendingMachineID,
		"weight_limit":        weightLimit,
		"current_weight":      currentWeight,
		"current_fill":        currentFill,
		"compatible_plastics": compatiblePlastics,
		"is_full":             currentWeight >= weightLimit,
	})
}

// RequestPickup godoc
// @Summary Request a vending machine pickup
// @Description Creates a pickup request for a full vending machine.
// @Tags Vendor Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param vending_machine_id path string true "Vending Machine ID"
// @Success 200 {object} map[string]string "Pickup requested successfully"
// @Failure 400 {object} map[string]string "Invalid vending machine ID or vending machine is not full"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /vendor-admin/vending-machine/{vending_machine_id}/pickup [post]
func RequestPickup(c echo.Context) error {
	// Extract vendor admin details from JWT claims
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	vendorID := claims["vendor_id"].(string)

	// Extract vending machine ID from the URL
	vendingMachineID := c.Param("vending_machine_id")
	if vendingMachineID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Vending machine ID is required"})
	}

	// Check if the vending machine is full
	var isFull bool
	query := `
		SELECT current_weight >= weight_limit AS is_full
		FROM vending_machines WHERE id = $1 AND vendor_id = $2
	`
	err := config.Pool.QueryRow(context.Background(), query, vendingMachineID, vendorID).Scan(&isFull)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch vending machine status"})
	}
	if !isFull {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Vending machine is not full"})
	}

	// Create a factory vendor request
	insertQuery := `
		INSERT INTO factory_vendor_requests (vendor_id, factory_id, vending_machine_id, status, created_at)
		VALUES ($1, (SELECT id FROM factories LIMIT 1), $2, 'Pending', NOW())
	`
	_, err = config.Pool.Exec(context.Background(), insertQuery, vendorID, vendingMachineID)
	if err != nil {
		fmt.Println(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to request pickup"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Pickup requested successfully"})
}
