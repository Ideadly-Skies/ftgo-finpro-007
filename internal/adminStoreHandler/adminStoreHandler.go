package Handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"ftgo-finpro/config/database"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgconn"
	"github.com/labstack/echo/v4"

	"github.com/midtrans/midtrans-go"
	"github.com/midtrans/midtrans-go/coreapi"
	"strings"
	"os"
)

// StoreAdmin struct
type StoreAdmin struct {
	ID        string `json:"id"`
	StoreID   string `json:"store_id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// RegisterRequest for store admin
type RegisterRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	StoreID  string `json:"store_id" validate:"required"`
}

// LoginRequest for store admin
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse for store admin
type LoginResponse struct {
	Token string `json:"token"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

var jwtSecret = []byte("12345")

// Initialize Midtrans Core API client
var coreAPI coreapi.Client

func Init() {
	// retrieve server key from .env
	ServerKey := os.Getenv("ServerKey")

	coreAPI = coreapi.Client{}
	coreAPI.New(ServerKey, midtrans.Sandbox)
}

// RegisterStoreAdmin handles store admin registration
func RegisterStoreAdmin(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Hash the password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	// Insert into store_admins table
	adminQuery := "INSERT INTO store_admins (name, email, password, store_id) VALUES ($1, $2, $3, $4) RETURNING id"
	var adminID string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = config.Pool.QueryRow(ctx, adminQuery, req.Name, req.Email, string(hashPassword), req.StoreID).Scan(&adminID)
	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Email already registered"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Store admin %s registered successfully", req.Name),
		"email":   req.Email,
	})
}

// LoginStoreAdmin handles store admin login
func LoginStoreAdmin(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Fetch admin details
	var admin StoreAdmin
	query := `SELECT id, store_id, name, email, password FROM store_admins WHERE email = $1`
	err := config.Pool.QueryRow(context.Background(), query, req.Email).Scan(
		&admin.ID, &admin.StoreID, &admin.Name, &admin.Email, &admin.Password,
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
		"admin_id": admin.ID,
		"name":     admin.Name,
		"email":    admin.Email,
		"store_id": admin.StoreID,
		"exp":      jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate token"})
	}

	// Update the JWT token in the database
	updateQuery := "UPDATE store_admins SET jwt_token = $1 WHERE id = $2"
	_, err = config.Pool.Exec(context.Background(), updateQuery, tokenString, admin.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update token"})
	}

	// Return login response
	return c.JSON(http.StatusOK, LoginResponse{
		Token: tokenString,
		Name:  admin.Name,
		Email: admin.Email,
	})
}

func FacilitatePurchase(c echo.Context) error {
    // Extract admin claims
    admin := c.Get("user").(*jwt.Token)
    adminClaims := admin.Claims.(jwt.MapClaims)
    storeID := adminClaims["store_id"].(string)

    // Bind the purchase request
    var req struct {
        CustomerID     string `json:"customer_id" validate:"required"`
        Items          []struct {
            Product  string  `json:"product" validate:"required"`
            Quantity int     `json:"quantity" validate:"required,min=1"`
        } `json:"items" validate:"required"`
        PaymentMethod string `json:"payment_method" validate:"required"` // "Wallet" or "Online"
    }
    
	if err := c.Bind(&req); err != nil || len(req.Items) == 0 {
        return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
    }

    // Fetch store inventory
    var storeProducts []struct {
        Product  string  `json:"product"`
        Price    float64 `json:"price"`
        Quantity int     `json:"quantity"`
    }
    storeQuery := "SELECT products FROM stores WHERE id = $1"
    var storeProductsJSON []byte
    if err := config.Pool.QueryRow(context.Background(), storeQuery, storeID).Scan(&storeProductsJSON); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch store inventory"})
    }
    if err := json.Unmarshal(storeProductsJSON, &storeProducts); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse store inventory"})
    }

    // Verify item availability and calculate total cost
    calculatedTotalCost := 0.0
	var itemDescriptions []string
    for _, item := range req.Items {
        found := false
        for i, product := range storeProducts {
            if product.Product == item.Product {
                if product.Quantity < item.Quantity {
                    return c.JSON(http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("Insufficient stock for %s", item.Product)})
                }
                storeProducts[i].Quantity -= item.Quantity
                calculatedTotalCost += product.Price * float64(item.Quantity)
				itemDescriptions = append(itemDescriptions, fmt.Sprintf("%s %dx", item.Product, item.Quantity))
                found = true
                break
            }
        }
        if !found {
            return c.JSON(http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("Product %s not found in store", item.Product)})
        }
    }

    if req.PaymentMethod == "Wallet" {
        // Wallet Payment Logic
        var customerBalance float64
        balanceQuery := "SELECT wallet_balance FROM customers WHERE id = $1"
        if err := config.Pool.QueryRow(context.Background(), balanceQuery, req.CustomerID).Scan(&customerBalance); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch customer wallet balance"})
        }
        if customerBalance < calculatedTotalCost {
            return c.JSON(http.StatusBadRequest, map[string]string{"message": "Insufficient wallet balance"})
        }

        // Deduct wallet balance
        updateWalletQuery := "UPDATE customers SET wallet_balance = wallet_balance - $1 WHERE id = $2"
        if _, err := config.Pool.Exec(context.Background(), updateWalletQuery, calculatedTotalCost, req.CustomerID); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update customer wallet balance"})
        }

		// Generate a unique order ID for the wallet transaction
		orderID := fmt.Sprintf("wallet-%s-%d", req.CustomerID[:8], time.Now().Unix())

		// Insert transaction into the customer_transactions table
		customerTransactionQuery := `
			INSERT INTO customer_transactions (id, customer_id, order_id, transaction_type, amount, status, is_processed, created_at, updated_at)
			VALUES (gen_random_uuid(), $1, $2, 'Purchase', $3, 'Completed', TRUE, NOW(), NOW())
		`
		if _, err := config.Pool.Exec(context.Background(), customerTransactionQuery, req.CustomerID, orderID, calculatedTotalCost); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to log transaction in customer_transactions"})
		}
			
    } else if req.PaymentMethod == "Online" {
		Init()

		// Generate Order ID
		orderID := fmt.Sprintf("store-%s-%d", storeID[:8], time.Now().Unix())

		// Create a description for Midtrans
		description := strings.Join(itemDescriptions, ", ")

		// Create a Midtrans charge request
		request := &coreapi.ChargeReq{
			PaymentType: coreapi.PaymentTypeBankTransfer,
			TransactionDetails: midtrans.TransactionDetails{
				OrderID:  orderID,
				GrossAmt: int64(calculatedTotalCost),
			},
			BankTransfer: &coreapi.BankTransferDetails{
				Bank: midtrans.BankBca,
			},
			CustomField1: &description, // Include item descriptions here
			CustomField2: &storeID,     // Store ID
		}

		// Send the charge request to Midtrans
		resp, err := coreAPI.ChargeTransaction(request)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to process online payment"})
		}

		if resp.TransactionStatus != "pending" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Payment not authorized"})
		}

		// Log the transaction as pending in customer_transactions table
		transactionQuery := `
			INSERT INTO customer_transactions (customer_id, order_id, transaction_type, amount, status, created_at, updated_at)
			VALUES ($1, $2, 'Purchase', $3, 'Pending', NOW(), NOW())
		`
		if _, err := config.Pool.Exec(context.Background(), transactionQuery, req.CustomerID, orderID, calculatedTotalCost); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to log transaction"})
		}
		
		// Return response
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":        "Purchase initiated successfully",
			"order_id":       orderID,
			"va_numbers":     resp.VaNumbers,
			"total_amount":   calculatedTotalCost,
			"transaction_id": resp.TransactionID,
		})
    }

    // Update store inventory
    updatedStoreProductsJSON, _ := json.Marshal(storeProducts)
    updateStoreQuery := "UPDATE stores SET products = $1 WHERE id = $2"
    if _, err := config.Pool.Exec(context.Background(), updateStoreQuery, updatedStoreProductsJSON, storeID); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update store inventory"})
    }

    // Update customer's inventory
    var customerInventory []struct {
        Product  string `json:"product"`
        Quantity int    `json:"quantity"`
    }
    customerInventoryQuery := "SELECT inventory FROM customers WHERE id = $1"
    var customerInventoryJSON []byte
    if err := config.Pool.QueryRow(context.Background(), customerInventoryQuery, req.CustomerID).Scan(&customerInventoryJSON); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch customer inventory"})
    }
    if err := json.Unmarshal(customerInventoryJSON, &customerInventory); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse customer inventory"})
    }
    for _, item := range req.Items {
        found := false
        for i, inventoryItem := range customerInventory {
            if inventoryItem.Product == item.Product {
                customerInventory[i].Quantity += item.Quantity
                found = true
                break
            }
        }
        if !found {
            customerInventory = append(customerInventory, struct {
                Product  string `json:"product"`
                Quantity int    `json:"quantity"`
            }{Product: item.Product, Quantity: item.Quantity})
        }
    }
    updatedCustomerInventoryJSON, _ := json.Marshal(customerInventory)
    updateCustomerInventoryQuery := "UPDATE customers SET inventory = $1 WHERE id = $2"
    if _, err := config.Pool.Exec(context.Background(), updateCustomerInventoryQuery, updatedCustomerInventoryJSON, req.CustomerID); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update customer inventory"})
    }

    // Insert transaction into store_transactions table (only for wallet payments)
    if req.PaymentMethod == "Wallet" {
        transactionQuery := `
            INSERT INTO store_transactions (customer_id, store_id, items, total_amount, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, 'Completed', NOW(), NOW())
        `
        itemsJSON, _ := json.Marshal(req.Items)
        if _, err := config.Pool.Exec(context.Background(), transactionQuery, req.CustomerID, storeID, itemsJSON, calculatedTotalCost); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to record transaction"})
        }
    }

    // Return success response
    return c.JSON(http.StatusOK, map[string]interface{}{
        "message":      "Purchase successful",
        "customer_id":  req.CustomerID,
        "store_id":     storeID,
        "total_amount": calculatedTotalCost,
        "items":        req.Items,
    })
}