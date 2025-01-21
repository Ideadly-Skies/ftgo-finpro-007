package models

type VerifyCustomerRequest struct {
	Email string `json:"email" validate:"required,email"`
}
