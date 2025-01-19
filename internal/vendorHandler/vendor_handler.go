package Handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	config "ftgo-finpro/config/database"

	"github.com/jackc/pgconn"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
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
	ID           string    `json:"id"`
	CustomerID   string    `json:"customer_id"`
	StoreAdminID string    `json:"store_admin_id"`
	VendorID     string    `json:"vendor_id"`
	Materials    string    `json:"materials"`       // Assuming JSONB will be stored as a JSON string
	NumberOfItems int      `json:"number_of_items"` // Integer field
	IsProcessed  bool      `json:"is_processed"`    // Boolean field
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
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

var jwtSecret = []byte("12345")

func RegisterVendorAdmin(c echo.Context) error {
	var req RegisterVendorAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
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

	err = config.Pool.QueryRow(ctx, adminQuery, req.Name, req.Email, string(hashPassword), req.VendorID).Scan(&adminID)
	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Email already registered"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Vendor admin %s registered successfully", req.Name),
		"email":   req.Email,
	})
}

func LoginVendorAdmin(c echo.Context) error {
	var req LoginVendorAdminRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

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
	tokenString, err := token.SignedString(jwtSecret)
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