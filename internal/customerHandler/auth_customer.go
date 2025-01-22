package handler

import (
	"context"
	"errors"
	"fmt"
	config "ftgo-finpro/config/database"
	"ftgo-finpro/internal/customerHandler/models"
	"ftgo-finpro/utils"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var jwtSecret = os.Getenv("JWT_SECRET")

// RegisterCustomer handles customer registration
func RegisterCustomer(c echo.Context) error {
	var req models.RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	if req.Name == "" || req.Email == "" || req.Password == "" {
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

	// Insert into customers table
	customerQuery := "INSERT INTO customers (name, email, password) VALUES ($1, $2, $3) RETURNING id"
	var customerID string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = config.Pool.QueryRow(ctx, customerQuery, req.Name, email, string(hashPassword)).Scan(&customerID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				return c.JSON(http.StatusBadRequest, map[string]string{"message": "Email already registered"})
			}
			log.Printf("PostgreSQL error: %v", err)
		}
	}

	if err = utils.SendRegisterNotification(req.Email, req.Name); err != nil {
		log.Printf("Failed to send email: %v", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Customer %s registered successfully", req.Name),
		"email":   email,
	})
}

// LoginCustomer handles customer login
func LoginCustomer(c echo.Context) error {
	var req models.LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Fetch customer details
	var customer models.Customer
	query := `SELECT id, name, email, password, wallet_balance, inventory, is_verified FROM customers WHERE email = $1`
	err := config.Pool.QueryRow(context.Background(), query, req.Email).Scan(
		&customer.ID, &customer.Name, &customer.Email, &customer.Password,
		&customer.WalletBalance, &customer.Inventory, &customer.IsVerified,
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
		"customer_id":    customer.ID,
		"name":           customer.Name,
		"email":          customer.Email,
		"wallet_balance": customer.WalletBalance,
		"inventory":      customer.Inventory,
		"is_verified":    customer.IsVerified,
		"exp":            jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
	})
	tokenString, err := token.SignedString([]byte(jwtSecret))
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
	return c.JSON(http.StatusOK, models.LoginResponse{
		Token:         tokenString,
		Name:          customer.Name,
		Email:         customer.Email,
		WalletBalance: customer.WalletBalance,
	})
}
