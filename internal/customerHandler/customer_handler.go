package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	config "ftgo-finpro/config/database"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/midtrans/midtrans-go"
	"github.com/midtrans/midtrans-go/coreapi"

	"encoding/json"
	"os"
	"strings"
)

// PaymentRequest represents a request for financial transactions like withdrawals or top-ups.
type PaymentRequest struct {
	Amount float64 `json:"amount" validate:"required"`
}

// Initialize Midtrans Core API client
var coreAPI coreapi.Client

func Init() {
	// retrieve server key from .env
	ServerKey := os.Getenv("ServerKey")

	coreAPI = coreapi.Client{}
	coreAPI.New(ServerKey, midtrans.Sandbox)
}

func GetWalletBalance(c echo.Context) error {
	// Extract customer ID from JWT claims
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	customerID := claims["customer_id"].(string) // Use string because UUIDs are stored as strings

	// Query wallet balance
	var balance float64
	query := "SELECT wallet_balance FROM customers WHERE id = $1"
	err := config.Pool.QueryRow(context.Background(), query, customerID).Scan(&balance)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to retrieve wallet balance"})
	}

	// Return wallet balance
	return c.JSON(http.StatusOK, map[string]interface{}{
		"wallet_balance": balance,
	})
}

func WithdrawMoney(c echo.Context) error {
	// Initialize Midtrans
	Init()

	// Extract customer ID from JWT claims
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	customerID := claims["customer_id"].(string) // UUID stored as a string
	customerName := claims["name"].(string)      // name of customer

	// Bind and validate request body
	var req PaymentRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}

	if req.Amount <= 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Withdraw amount must be greater than zero"})
	}

	// Generate order ID
	orderID := fmt.Sprintf("wd-%s-%d", customerID[:8], time.Now().Unix())

	// Generate Customer Field Value
	customFieldValue := fmt.Sprintf("facilitating withdraw request for %s", customerName)

	// Create a Midtrans charge request
	request := &coreapi.ChargeReq{
		PaymentType: coreapi.PaymentTypeBankTransfer,
		TransactionDetails: midtrans.TransactionDetails{
			OrderID:  orderID,
			GrossAmt: int64(req.Amount), // Midtrans uses IDR natively
		},
		BankTransfer: &coreapi.BankTransferDetails{
			Bank: midtrans.BankBca, // Use a specific bank for withdrawals
		},
		CustomField1: &customFieldValue,
	}

	// Send the charge request to Midtrans
	resp, err := coreAPI.ChargeTransaction(request)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to process withdrawal"})
	}

	// Check if VA numbers exist
	var vaNumber, bank string
	if len(resp.VaNumbers) > 0 {
		vaNumber = resp.VaNumbers[0].VANumber // Get the first VA number
		bank = resp.VaNumbers[0].Bank         // Get the bank name
	} else {
		vaNumber = "No virtual account number available" // Fallback if no VA is provided
		bank = "Unknown"
	}

	// Insert the transaction into the customer_transactions table
	transactionQuery := `
		INSERT INTO customer_transactions (customer_id, order_id, transaction_type, amount, status, created_at, updated_at)
		VALUES ($1, $2, 'Withdraw', $3, 'Pending', NOW(), NOW())
	`
	_, txnErr := config.Pool.Exec(context.Background(), transactionQuery, customerID, orderID, req.Amount)
	if txnErr != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to log transaction"})
	}

	// Return withdrawal details with VA number
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":        "Withdrawal initiated successfully",
		"transaction_id": resp.TransactionID,
		"order_id":       resp.OrderID,
		"va_number":      vaNumber,
		"bank":           bank,
		"gross_amount":   resp.GrossAmount,
		"status":         resp.TransactionStatus,
	})
}

// check withdrawal status for customer
func CheckWithdrawalStatus(c echo.Context) error {
	Init() // Initialize Midtrans

	orderID := c.Param("order_id") // Extract Order ID from request URL

	// Check if the transaction has already been processed
	var isProcessed bool
	checkProcessedQuery := "SELECT is_processed FROM customer_transactions WHERE order_id = $1"
	if err := config.Pool.QueryRow(context.Background(), checkProcessedQuery, orderID).Scan(&isProcessed); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to check transaction processing status"})
	}
	if isProcessed {
		return c.JSON(http.StatusConflict, map[string]string{"message": "Transaction has already been processed"})
	}

	// Fetch transaction status from Midtrans
	resp, err := coreAPI.CheckTransaction(orderID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch transaction status"})
	}

	// Update transaction status in the database
	updateQuery := "UPDATE customer_transactions SET status = $1, updated_at = NOW() WHERE order_id = $2"
	_, dbErr := config.Pool.Exec(context.Background(), updateQuery, resp.TransactionStatus, orderID)
	if dbErr != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update transaction status"})
	}

	// If the transaction is successful, update the customer's wallet balance
	if resp.TransactionStatus == "settlement" {
		// Get the transaction amount and customer ID from the database
		var amount float64
		var customerID string
		selectQuery := "SELECT amount, customer_id FROM customer_transactions WHERE order_id = $1"
		row := config.Pool.QueryRow(context.Background(), selectQuery, orderID)
		if err := row.Scan(&amount, &customerID); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch transaction details"})
		}

		// Add the transaction amount to the customer's wallet balance
		updateWalletBalance := "UPDATE customers SET wallet_balance = wallet_balance + $1 WHERE id = $2"
		_, err := config.Pool.Exec(context.Background(), updateWalletBalance, amount, customerID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update wallet balance"})
		}

		// Mark the transaction as processed
		markProcessedQuery := "UPDATE customer_transactions SET is_processed = TRUE WHERE order_id = $1"
		_, dbErr = config.Pool.Exec(context.Background(), markProcessedQuery, orderID)
		if dbErr != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to mark transaction as processed"})
		}
	}

	// Return the transaction status
	return c.JSON(http.StatusOK, map[string]interface{}{
		"order_id":       resp.OrderID,
		"transaction_id": resp.TransactionID,
		"status":         resp.TransactionStatus,
		"payment_type":   resp.PaymentType,
		"gross_amount":   resp.GrossAmount,
	})
}

func CheckPurchaseStatus(c echo.Context) error {
	Init() // Initialize Midtrans

	orderID := c.Param("order_id") // Extract Order ID from the request URL

	// Check if the transaction has already been processed
	var isProcessed bool
	checkProcessedQuery := "SELECT is_processed FROM customer_transactions WHERE order_id = $1"
	if err := config.Pool.QueryRow(context.Background(), checkProcessedQuery, orderID).Scan(&isProcessed); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to check transaction processing status"})
	}
	if isProcessed {
		return c.JSON(http.StatusConflict, map[string]string{"message": "Transaction has already been processed"})
	}

	// Fetch transaction status from Midtrans
	resp, err := coreAPI.CheckTransaction(orderID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch transaction status"})
	}

	// Update the customer_transactions table with the latest status
	updateCustomerTransactionQuery := "UPDATE customer_transactions SET status = $1, updated_at = NOW() WHERE order_id = $2"
	_, dbErr := config.Pool.Exec(context.Background(), updateCustomerTransactionQuery, resp.TransactionStatus, orderID)
	if dbErr != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update customer transaction status"})
	}

	// If the transaction is successful, process the purchase
	if resp.TransactionStatus == "settlement" {
		// Parse purchased items from CustomField1
		purchasedItems := []struct {
			Product  string `json:"product"`
			Quantity int    `json:"quantity"`
		}{}
		itemDescription := resp.CustomField1
		if itemDescription == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Item details missing from transaction"})
		}

		// Parse the items
		items := strings.Split(itemDescription, ", ")
		for _, item := range items {
			splitIndex := strings.LastIndex(item, " x")
			if splitIndex == -1 {
				continue // Skip invalid items
			}

			product := strings.TrimSpace(item[:splitIndex]) // Extract product name
			var quantity int
			_, err := fmt.Sscanf(item[splitIndex+2:], "%d", &quantity) // Parse quantity
			if err != nil {
				continue
			}

			purchasedItems = append(purchasedItems, struct {
				Product  string `json:"product"`
				Quantity int    `json:"quantity"`
			}{Product: product, Quantity: quantity})
		}

		// Fetch the store ID and customer ID
		storeID := resp.CustomField2
		var customerID string
		fetchCustomerIDQuery := "SELECT customer_id FROM customer_transactions WHERE order_id = $1"
		if err := config.Pool.QueryRow(context.Background(), fetchCustomerIDQuery, orderID).Scan(&customerID); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch customer ID"})
		}

		// Fetch store inventory
		var storeProducts []struct {
			Product  string  `json:"product"`
			Price    float64 `json:"price"`
			Weight   float64 `json:"weight"`
			Quantity int     `json:"quantity"`
		}
		var productTypes []string // product types to update the customer inventory with
		fetchStoreInventoryQuery := "SELECT products, product_types FROM stores WHERE id = $1"
		var storeProductsJSON, productTypesJSON []byte
		if err := config.Pool.QueryRow(context.Background(), fetchStoreInventoryQuery, storeID).Scan(&storeProductsJSON, &productTypesJSON); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch store inventory"})
		}
		if err := json.Unmarshal(storeProductsJSON, &storeProducts); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse store inventory"})
		}
		if err := json.Unmarshal(productTypesJSON, &productTypes); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse product types"})
		}

		// Create a productTypeMap to add to the customer's inventory
		productTypeMap := make(map[string]string)
		for i, product := range storeProducts {
			if i < len(productTypes) {
				productTypeMap[product.Product] = productTypes[i]
			}
		}

		// Fetch customer inventory
		var customerInventory []struct {
			Product  string  `json:"product"`
			Quantity int     `json:"quantity"`
			Weight   float64 `json:"weight"`
			Type     string  `json:"type"`
		}
		fetchCustomerInventoryQuery := "SELECT inventory FROM customers WHERE id = $1"
		var customerInventoryJSON []byte
		if err := config.Pool.QueryRow(context.Background(), fetchCustomerInventoryQuery, customerID).Scan(&customerInventoryJSON); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch customer inventory"})
		}
		if err := json.Unmarshal(customerInventoryJSON, &customerInventory); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse customer inventory"})
		}

		// Process the inventory updates
		for _, purchasedItem := range purchasedItems {
			// Update store inventory
			for i, storeProduct := range storeProducts {
				if storeProduct.Product == purchasedItem.Product {
					if storeProduct.Quantity < purchasedItem.Quantity {
						return c.JSON(http.StatusBadRequest, map[string]string{
							"message": fmt.Sprintf("Insufficient stock for %s", storeProduct.Product),
						})
					}
					storeProducts[i].Quantity -= purchasedItem.Quantity
					break
				}
			}

			// Update customer inventory
			found := false
			for i, inventoryItem := range customerInventory {
				if inventoryItem.Product == purchasedItem.Product {
					for _, storeProduct := range storeProducts {
						if storeProduct.Product == purchasedItem.Product {
							customerInventory[i].Quantity += purchasedItem.Quantity
							customerInventory[i].Weight += float64(purchasedItem.Quantity) * storeProduct.Weight
							break
						}
					}
					found = true
					break
				}
			}
			if !found {
				for _, storeProduct := range storeProducts {
					if storeProduct.Product == purchasedItem.Product {
						customerInventory = append(customerInventory, struct {
							Product  string  `json:"product"`
							Quantity int     `json:"quantity"`
							Weight   float64 `json:"weight"`
							Type     string  `json:"type"`
						}{
							Product:  purchasedItem.Product,
							Quantity: purchasedItem.Quantity,
							Weight:   float64(purchasedItem.Quantity) * storeProduct.Weight,
							Type:     productTypeMap[purchasedItem.Product],
						})
						break
					}
				}
			}
		}

		// Save updated inventories to the database
		updatedStoreProductsJSON, _ := json.Marshal(storeProducts)
		updateStoreInventoryQuery := "UPDATE stores SET products = $1 WHERE id = $2"
		_, execErr := config.Pool.Exec(context.Background(), updateStoreInventoryQuery, updatedStoreProductsJSON, storeID)
		if execErr != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update store inventory"})
		}

		updatedCustomerInventoryJSON, _ := json.Marshal(customerInventory)
		_, dbErr := config.Pool.Exec(context.Background(), "UPDATE customers SET inventory = $1 WHERE id = $2", updatedCustomerInventoryJSON, customerID)
		if dbErr != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update customer inventory"})
		}

		// Mark the transaction as processed
		_, dbErr = config.Pool.Exec(context.Background(), "UPDATE customer_transactions SET is_processed = TRUE WHERE order_id = $1", orderID)
		if dbErr != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to mark transaction as processed"})
		}

		// Log the transaction in the store_transactions table
		transactionQuery := `
			INSERT INTO store_transactions (customer_id, store_id, items, total_amount, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 'Completed', NOW(), NOW())
		`
		purchasedItemsJSON, _ := json.Marshal(purchasedItems)
		if _, err := config.Pool.Exec(context.Background(), transactionQuery, customerID, storeID, purchasedItemsJSON, resp.GrossAmount); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to record transaction"})
		}
	}

	// Return the transaction status
	return c.JSON(http.StatusOK, map[string]interface{}{
		"order_id":       resp.OrderID,
		"transaction_id": resp.TransactionID,
		"status":         resp.TransactionStatus,
		"payment_type":   resp.PaymentType,
		"gross_amount":   resp.GrossAmount,
	})
}

func GetCustomerTokens(c echo.Context) error {
	// Extract customer ID from JWT claims
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	customerID, ok := claims["customer_id"].(string)
	if !ok || customerID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"message": "Unauthorized: Missing or invalid customer ID",
		})
	}

	// Query to fetch all tokens for the logged-in customer
	query := `
        SELECT id, vendor_id, token, issued_at, is_redeemed
        FROM customer_tokens
        WHERE customer_id = $1
        ORDER BY issued_at DESC
    `
	rows, err := config.Pool.Query(context.Background(), query, customerID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"message": "Failed to fetch customer tokens",
		})
	}
	defer rows.Close()

	// Collect tokens into a slice
	var tokens []struct {
		ID         string    `json:"id"`
		VendorID   string    `json:"vendor_id"`
		Token      string    `json:"token"`
		IssuedAt   time.Time `json:"issued_at"`
		IsRedeemed bool      `json:"is_redeemed"`
	}

	for rows.Next() {
		var token struct {
			ID         string    `json:"id"`
			VendorID   string    `json:"vendor_id"`
			Token      string    `json:"token"`
			IssuedAt   time.Time `json:"issued_at"`
			IsRedeemed bool      `json:"is_redeemed"`
		}
		if err := rows.Scan(&token.ID, &token.VendorID, &token.Token, &token.IssuedAt, &token.IsRedeemed); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"message": "Failed to parse tokens",
			})
		}
		tokens = append(tokens, token)
	}

	// Return tokens in JSON format
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Customer tokens fetched successfully",
		"tokens":  tokens,
	})
}

func GetAllStoreCoordinate(c echo.Context) error {
	// Query to fetch all store coordinates
	query := `
		SELECT store_name, coordinate
		FROM store_coordinates
	`
	rows, err := config.Pool.Query(context.Background(), query)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"message": "Failed to fetch store coordinates",
		})
	}
	defer rows.Close()

	// Collect store coordinates into a slice
	var stores []struct {
		Name       string `json:"store_name"`
		Coordinate string `json:"coordinate"`
	}

	for rows.Next() {
		var store struct {
			Name       string `json:"store_name"`
			Coordinate string `json:"coordinate"`
		}
		if err = rows.Scan(&store.Name, &store.Coordinate); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"message": "Failed to parse store coordinates",
			})
		}
		stores = append(stores, store)
	}

	// Return store coordinates in JSON format
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "We found the store locations for you!",
		"stores":  stores,
	})
}
