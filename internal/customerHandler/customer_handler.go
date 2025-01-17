package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	config "ftgo-finpro/config/database"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgconn"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

// Customer struct
type Customer struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Email          string  `json:"email"`
	Password       string  `json:"password"`
	JwtToken       string  `json:"jwt_token"`
	WalletBalance  float64 `json:"wallet_balance"`
	TokenList      string  `json:"token_list"`
	Inventory      string  `json:"inventory"`
	IsVerified     bool    `json:"is_verified"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

// RegisterRequest struct
type RegisterRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginRequest struct
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse struct
type LoginResponse struct {
	Token        string  `json:"token"`
	Name         string  `json:"name"`
	Email        string  `json:"email"`
	WalletBalance float64 `json:"wallet_balance"`
}

var jwtSecret = []byte("12345")

// RegisterCustomer handles customer registration
func RegisterCustomer(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Hash the password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	// Insert into customers table
	customerQuery := "INSERT INTO customers (name, email, password) VALUES ($1, $2, $3) RETURNING id"
	var customerID string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = config.Pool.QueryRow(ctx, customerQuery, req.Name, req.Email, string(hashPassword)).Scan(&customerID)
	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Email already registered"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Customer %s registered successfully", req.Name),
		"email":   req.Email,
	})
}

// LoginCustomer handles customer login
func LoginCustomer(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Fetch customer details
	var customer Customer
	query := `SELECT id, name, email, password, wallet_balance, token_list, inventory, is_verified FROM customers WHERE email = $1`
	err := config.Pool.QueryRow(context.Background(), query, req.Email).Scan(
		&customer.ID, &customer.Name, &customer.Email, &customer.Password,
		&customer.WalletBalance, &customer.TokenList, &customer.Inventory, &customer.IsVerified,
	)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(customer.Password), []byte(req.Password)); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"customer_id":   customer.ID,
		"name":          customer.Name,
		"email":         customer.Email,
		"wallet_balance": customer.WalletBalance,
		"token_list":    customer.TokenList,
		"inventory":     customer.Inventory,
		"is_verified":   customer.IsVerified,
		"exp":           jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate token"})
	}

	// Update JWT token in the database
	updateQuery := "UPDATE customers SET jwt_token = $1 WHERE id = $2"
	_, err = config.Pool.Exec(context.Background(), updateQuery, tokenString, customer.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update token"})
	}

	// Return login response
	return c.JSON(http.StatusOK, LoginResponse{
		Token:         tokenString,
		Name:          customer.Name,
		Email:         customer.Email,
		WalletBalance: customer.WalletBalance,
	})
}