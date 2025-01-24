package handler

import (
	"context"
	"encoding/json"
	"fmt"
	config "ftgo-finpro/config/database"
	"ftgo-finpro/internal/customerHandler/models"
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/midtrans/midtrans-go"
	"github.com/midtrans/midtrans-go/coreapi"
	"math"
	"net/http"
	"os"
	"strings"
	"time"
)

// FacilitatePurchaseOnline godoc
// @Summary Facilitate an online purchase
// @Description Handles customer purchase requests and processes payments via wallet or online methods.
// @Tags Purchases
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param purchaseRequest body FacilitatePurchaseRequest true "Purchase Request Body"
// @Success 200 {object} models.PurchaseResponse "Purchase successful"
// @Failure 400 {object} map[string]string "Invalid request or insufficient stock/wallet balance"
// @Failure 500 {object} map[string]string "Failed to process purchase or update inventory"
// @Router /purchase/online [post]
func FacilitatePurchaseOnline(c echo.Context) error {
	// Extract admin claims
	admin := c.Get("user").(*jwt.Token)
	adminClaims := admin.Claims.(jwt.MapClaims)
	storeID := adminClaims["store_id"].(string)

	// Bind the purchase request
	var req struct {
		CustomerID string `json:"customer_id" validate:"required"`
		Items      []struct {
			Product  string `json:"product" validate:"required"`
			Quantity int    `json:"quantity" validate:"required,min=1"`
		} `json:"items" validate:"required"`
		PaymentMethod string `json:"payment_method" validate:"required"` // "Wallet" or "Online"
		Origin        string `json:"origin" validate:"required"`
		Destination   string `json:"destination" validate:"required"`
	}

	if err := c.Bind(&req); err != nil || len(req.Items) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
	}

	// Panggil fungsi untuk menghitung jarak dan biaya pengiriman
	distanceResponse, err := CalculateDistanceAndPriceWithResponse(req.Origin, req.Destination)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Error calculating distance"})
	}

	// Fetch store inventory
	var storeProducts []struct {
		Product  string  `json:"product"`
		Price    float64 `json:"price"`
		Weight   float64 `json:"weight"` // include weight in here
		Quantity int     `json:"quantity"`
	}
	var productTypes []string

	storeQuery := "SELECT products, product_types FROM stores WHERE id = $1"
	var storeProductsJSON, productTypesJSON []byte
	if err := config.Pool.QueryRow(context.Background(), storeQuery, storeID).Scan(&storeProductsJSON, &productTypesJSON); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch store inventory"})
	}
	if err := json.Unmarshal(storeProductsJSON, &storeProducts); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse store inventory"})
	}
	if err := json.Unmarshal(productTypesJSON, &productTypes); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse product types"})
	}

	// Create a map of product types
	productTypeMap := make(map[string]string)
	for i, product := range storeProducts {
		if i < len(productTypes) {
			productTypeMap[product.Product] = productTypes[i]
		}
	}

	// Verify item availability and calculate total cost
	calculatedTotalCost := 0.0
	var itemDescriptions []string

	// Create a set of valid products for validation
	validProducts := make(map[string]bool)
	for _, product := range storeProducts {
		validProducts[product.Product] = true
	}

	// Check if all requested products are valid
	for _, item := range req.Items {
		if !validProducts[item.Product] {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"message": fmt.Sprintf("Invalid product: %s", item.Product),
			})
		}
	}

	// Validate item quantities
	for _, item := range req.Items {
		if item.Quantity <= 0 {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"message": fmt.Sprintf("Invalid quantity for product: %s. Quantity must be greater than 0", item.Product),
			})
		}
	}

	for _, item := range req.Items {
		for i, product := range storeProducts {
			if product.Product == item.Product {
				if product.Quantity < item.Quantity {
					return c.JSON(http.StatusBadRequest, map[string]string{
						"message": fmt.Sprintf("Insufficient stock for %s", item.Product),
					})
				}
				// Reduce the quantity and retain the weight
				storeProducts[i].Quantity -= item.Quantity

				// Add the cost for this item to the total
				calculatedTotalCost += product.Price * float64(item.Quantity)

				// Add description for Midtrans payload
				itemDescriptions = append(itemDescriptions, fmt.Sprintf("%s x%d", product.Product, item.Quantity))
				break
			}
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

		finalprice := distanceResponse.Price + calculatedTotalCost

		// Create a Midtrans charge request
		request := &coreapi.ChargeReq{
			PaymentType: coreapi.PaymentTypeBankTransfer,
			TransactionDetails: midtrans.TransactionDetails{
				OrderID:  orderID,
				GrossAmt: int64(finalprice),
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

		var vaNumbers []models.VANumber
		for _, va := range resp.VaNumbers {
			vaNumbers = append(vaNumbers, models.VANumber{
				Bank:     va.Bank,
				VANumber: va.VANumber,
			})
		}
		finalprice = distanceResponse.Price + calculatedTotalCost
		response := models.PurchaseOnlineResponse{
			Message:     "Purchase successful",
			CustomerID:  req.CustomerID,
			StoreID:     storeID,
			TotalAmount: calculatedTotalCost,
			DeliveryFee: distanceResponse.Price,
			FinalPrice:  finalprice,
			VaNumbers:   vaNumbers,
			DistanceKm:  distanceResponse.DistanceKm,
		}
		return c.JSON(http.StatusOK, response)
	}

	// Update store inventory
	updatedStoreProductsJSON, _ := json.Marshal(storeProducts)
	updateStoreQuery := "UPDATE stores SET products = $1 WHERE id = $2"
	if _, err := config.Pool.Exec(context.Background(), updateStoreQuery, updatedStoreProductsJSON, storeID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"message": "Failed to update store inventory",
		})
	}

	// Update customer's inventory
	var customerInventory []struct {
		Product  string  `json:"product"`
		Quantity int     `json:"quantity"`
		Weight   float64 `json:"weight"`
		Type     string  `json:"type"`
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
				// Update existing inventory item
				for _, product := range storeProducts {
					if product.Product == item.Product {
						customerInventory[i].Quantity += item.Quantity
						customerInventory[i].Weight += float64(item.Quantity) * product.Weight
						break
					}
				}
				found = true
				break
			}
		}
		if !found {
			// Add a new item to the inventory
			for _, product := range storeProducts {
				if product.Product == item.Product {
					customerInventory = append(customerInventory, struct {
						Product  string  `json:"product"`
						Quantity int     `json:"quantity"`
						Weight   float64 `json:"weight"`
						Type     string  `json:"type"`
					}{
						Product:  item.Product,
						Quantity: item.Quantity,
						Weight:   float64(item.Quantity) * product.Weight,
						Type:     productTypeMap[item.Product],
					})
					break
				}
			}
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

	var items []models.Item
	for _, item := range req.Items {
		items = append(items, models.Item{
			Product:  item.Product,
			Quantity: item.Quantity,
		})
	}

	finalprice := distanceResponse.Price + calculatedTotalCost

	response := models.PurchaseResponse{
		Message:     "Purchase successful",
		CustomerID:  req.CustomerID,
		StoreID:     storeID,
		TotalAmount: calculatedTotalCost,
		DeliveryFee: distanceResponse.Price,
		FinalPrice:  finalprice,
		Items:       items,
		DistanceKm:  distanceResponse.DistanceKm,
	}

	return c.JSON(http.StatusOK, response)

}

func CalculateDistanceAndPriceWithResponse(origin, destination string) (*models.DistanceResponse, error) {
	PricePerKm := 5000.0

	// Call Google Maps Distance Matrix API
	distance, err := getDistanceFromAPI(origin, destination)
	if err != nil {
		return nil, err
	}

	// Sum the distance and calculate the price
	distanceInKm := float64(distance) / 1000 // Convert meters to kilometers
	price := distanceInKm * PricePerKm

	roundedPrice := math.Round(price/1000) * 1000 // Round to the nearest thousand

	return &models.DistanceResponse{
		Origin:      origin,
		Destination: destination,
		DistanceKm:  distanceInKm,
		Price:       roundedPrice,
		PricePerKm:  PricePerKm,
	}, nil
}

func getDistanceFromAPI(origin, destination string) (int, error) {
	apiKey := os.Getenv("GOOGLE_MAPS_API_KEY")
	if apiKey == "" {
		return 0, fmt.Errorf("Google Maps API key not configured")
	}

	url := fmt.Sprintf("https://maps.googleapis.com/maps/api/distancematrix/json?origins=%s&destinations=%s&key=%s", origin, destination, apiKey)
	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("failed to call Google Maps API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Google Maps API returned status: %s", resp.Status)
	}

	var result models.DistanceMatrixResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to parse Google Maps API response: %v", err)
	}

	if len(result.Rows) == 0 || len(result.Rows[0].Elements) == 0 {
		return 0, fmt.Errorf("no data found in Google Maps API response")
	}

	element := result.Rows[0].Elements[0]
	if element.Status != "OK" {
		return 0, fmt.Errorf("error from Google Maps API: %s", element.Status)
	}

	return element.Distance.Value, nil
}
