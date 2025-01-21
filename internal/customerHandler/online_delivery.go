package handler

import (
	"encoding/json"
	"fmt"
	"ftgo-finpro/internal/customerHandler/models"
	"github.com/labstack/echo/v4"
	"math"
	"net/http"
	"os"
)

func CalculateDistanceAndPrice(c echo.Context) error {
	PricePerKm := 5000.0

	// Bind JSON body ke struct
	var req models.DistanceRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "invalid request body",
		})
	}

	if req.Origin == "" || req.Destination == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "origin and destination are required",
		})
	}

	// Call Google Maps Distance Matrix API
	distance, err := getDistanceFromAPI(req.Origin, req.Destination)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": err.Error(),
		})
	}

	// Calculate price
	distanceInKm := float64(distance) / 1000 // Convert meters to kilometers
	price := distanceInKm * PricePerKm

	roundedPrice := math.Round(price/1000) * 1000 // Round to the nearest thousand

	return c.JSON(http.StatusOK, echo.Map{
		"origin":       req.Origin,
		"destination":  req.Destination,
		"distance_km":  distanceInKm,
		"price":        roundedPrice,
		"price_per_km": PricePerKm,
	})
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
