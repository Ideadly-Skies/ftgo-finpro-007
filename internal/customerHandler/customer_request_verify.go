package handler

import (
	"ftgo-finpro/utils"
	"github.com/labstack/echo/v4"
	"log"
	"net/http"
)

type VerifyRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func RequestVerify(c echo.Context) error {
	var req VerifyRequest

	// Bind request body ke struct
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request body"})
	}

	// Validasi input
	if req.Email == "" || req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Email and name are required"})
	}

	// Kirim notifikasi/email
	if err := utils.SendEmailNotification(req.Email, req.Name); err != nil {
		log.Printf("Failed to send email: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to send email"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Your verification request has been received, kindly check your email regularly."})
}
