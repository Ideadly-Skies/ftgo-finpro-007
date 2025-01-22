package handler

import (
	"context"
	config "ftgo-finpro/config/database"
	"ftgo-finpro/internal/adminStoreHandler/models"
	"ftgo-finpro/utils"
	"github.com/labstack/echo/v4"
	"log"
	"net/http"
)

func VerifyCustomer(c echo.Context) error {
	var req models.VerifyCustomerRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}

	if req.Email == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email"})
	}

	if !utils.ValidateEmail(req.Email) {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email format"})
	}

	var isVerified bool
	checkQuery := "SELECT is_verified FROM customers WHERE email = $1"
	err := config.Pool.QueryRow(context.Background(), checkQuery, req.Email).Scan(&isVerified)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "Customer not found"})
		}
		log.Printf("Error checking customer: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to check verification status"})
	}

	if isVerified {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Customer already verified"})
	}

	updateQuery := "UPDATE customers SET is_verified = TRUE WHERE email = $1"
	result, err := config.Pool.Exec(context.Background(), updateQuery, req.Email)
	if err != nil {
		log.Printf("Error verifying customer: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to verify customer"})
	}

	if result.RowsAffected() == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"message": "Customer not found"})
	}

	// Kirim notifikasi/email
	if err = utils.SendEmailVerifNotification(req.Email); err != nil {
		log.Printf("Failed to send email: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to send email"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Customer verified successfully"})
}
