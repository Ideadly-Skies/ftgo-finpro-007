package handler

import (
	"context"
	config "ftgo-finpro/config/database"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"

	"fmt"
	"github.com/jackc/pgconn"
	"golang.org/x/crypto/bcrypt"
	"time"
)


// RegisterFactoryAdminRequest defines the request body for registering a factory admin
type RegisterFactoryAdminRequest struct {
	Name      string `json:"name" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required"`
	FactoryID string `json:"factory_id" validate:"required"`
}

// LoginFactoryAdminRequest defines the request body for logging w/ a factory admin account
type LoginFactoryAdminRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

var jwtSecret = os.Getenv("JWT_SECRET") // for jwt middleware

// RegisterFactoryAdmin godoc
// @Summary Register a factory admin
// @Description Registers a new factory admin with a name, email, password, and associated factory ID.
// @Tags Factory Admin
// @Accept json
// @Produce json
// @Param body body handler.RegisterFactoryAdminRequest true "Register Factory Admin Request"
// @Success 200 {object} map[string]interface{} "Admin registered successfully"
// @Failure 400 {object} map[string]string "Invalid request or email already registered"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /factory-admin/register [post]
func RegisterFactoryAdmin(c echo.Context) error {
	var req struct {
		Name      string `json:"name" validate:"required"`
		Email     string `json:"email" validate:"required,email"`
		Password  string `json:"password" validate:"required"`
		FactoryID string `json:"factory_id" validate:"required"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}

	// Hash the password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to hash password"})
	}

	// Insert into factory_admins table
	adminQuery := `
		INSERT INTO factory_admins (name, email, password, factory_id) 
		VALUES ($1, $2, $3, $4) RETURNING id
	`
	var adminID string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = config.Pool.QueryRow(ctx, adminQuery, req.Name, req.Email, string(hashPassword), req.FactoryID).Scan(&adminID)
	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Email already registered"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to register factory admin"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Factory admin %s registered successfully", req.Name),
		"email":   req.Email,
	})
}

// LoginFactoryAdmin godoc
// @Summary Login for factory admin
// @Description Authenticates a factory admin using their email and password and returns a JWT token.
// @Tags Factory Admin
// @Accept json
// @Produce json
// @Param body body handler.LoginFactoryAdminRequest true "Login Factory Admin Request"
// @Success 200 {object} map[string]interface{} "Login successful with token"
// @Failure 400 {object} map[string]string "Invalid email or password"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /factory-admin/login [post]
func LoginFactoryAdmin(c echo.Context) error {
	var req struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}

	// Fetch admin details from the database
	var admin struct {
		ID        string `json:"id"`
		FactoryID string `json:"factory_id"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}
	query := `
		SELECT id, factory_id, name, email, password 
		FROM factory_admins WHERE email = $1
	`
	err := config.Pool.QueryRow(context.Background(), query, req.Email).Scan(
		&admin.ID, &admin.FactoryID, &admin.Name, &admin.Email, &admin.Password,
	)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Compare the provided password with the hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(req.Password)); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Generate a JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"admin_id":   admin.ID,
		"name":       admin.Name,
		"email":      admin.Email,
		"factory_id": admin.FactoryID,
		"exp":        jwt.NewNumericDate(time.Now().Add(72 * time.Hour)), // 72-hour expiration
	})
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate token"})
	}

	// Update the JWT token in the database
	updateQuery := `UPDATE factory_admins SET jwt_token = $1 WHERE id = $2`
	_, err = config.Pool.Exec(context.Background(), updateQuery, tokenString, admin.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update token"})
	}

	// Return the login response
	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":      tokenString,
		"name":       admin.Name,
		"email":      admin.Email,
		"factory_id": admin.FactoryID,
	})
}

// ProcessFactoryRequest godoc
// @Summary Process a factory vendor request
// @Description Processes a pending vendor request for a specific vending machine, updates vendor revenue, and resets the vending machine.
// @Tags Factory Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request_id path string true "Request ID"
// @Success 200 {object} map[string]interface{} "Request processed successfully"
// @Failure 400 {object} map[string]string "Invalid request ID or unauthorized access"
// @Failure 404 {object} map[string]string "Request or vending machine not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /factory-admin/request/{request_id} [post]
func ProcessFactoryRequest(c echo.Context) error {
	// Extract factory admin details from JWT claims
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	factoryID := claims["factory_id"].(string)

	// Extract request ID from the URL
	requestID := c.Param("request_id")
	if requestID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Request ID is required"})
	}

	// Fetch request details
	var vendorID, vendingMachineID string
	query := `
		SELECT vendor_id, vending_machine_id
		FROM factory_vendor_requests
		WHERE id = $1 AND factory_id = $2 AND status = 'Pending'
	`
	err := config.Pool.QueryRow(context.Background(), query, requestID, factoryID).Scan(&vendorID, &vendingMachineID)
	if err != nil {
		fmt.Println(err)
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid or unauthorized request"})
	}

	// Fetch vending machine details
	var currentWeight float64
	var compatiblePlastics []string
	vendingMachineQuery := `
		SELECT current_weight, compatible_plastics 
		FROM vending_machines WHERE id = $1
	`
	err = config.Pool.QueryRow(context.Background(), vendingMachineQuery, vendingMachineID).Scan(&currentWeight, &compatiblePlastics)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch vending machine details"})
	}

	// Fetch plastic pricing
	pricingQuery := `SELECT type, price_per_kg_factory FROM plastics_pricing`
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

	// Calculate payout
	totalPayout := 0.0
	for _, plasticType := range compatiblePlastics {
		totalPayout += currentWeight * pricing[plasticType]
	}

	// Update vendor's revenue
	updateVendorQuery := `
		UPDATE vendors SET revenue = revenue + $1 WHERE id = $2
	`
	_, err = config.Pool.Exec(context.Background(), updateVendorQuery, totalPayout, vendorID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update vendor revenue"})
	}

	// Reset vending machine
	resetVendingMachineQuery := `
		UPDATE vending_machines SET current_weight = 0, current_fill = 0 WHERE id = $1
	`
	_, err = config.Pool.Exec(context.Background(), resetVendingMachineQuery, vendingMachineID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to reset vending machine"})
	}

	// Update request status
	updateRequestQuery := `
		UPDATE factory_vendor_requests SET status = 'Completed' WHERE id = $1
	`
	_, err = config.Pool.Exec(context.Background(), updateRequestQuery, requestID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update request status"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":     "Request processed successfully",
		"vendor_id":   vendorID,
		"payout":      totalPayout,
		"machine_id":  vendingMachineID,
		"new_revenue": totalPayout,
	})
}
