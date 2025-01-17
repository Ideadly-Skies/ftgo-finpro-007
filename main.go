package main
import (
	"ftgo-finpro/config/database"
	customer_handler "ftgo-finpro/internal/customerHandler"

	
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main(){
	// migrate data to supabase
	// config.MigrateData()

	// connect to db
	config.InitDB()
	defer config.CloseDB()
	
	// use echo-framework to simulate smart-city ecosystem
	e := echo.New()
	
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	
	// public routes
	e.POST("/customer/register", customer_handler.RegisterCustomer)
	e.POST("/customer/login", customer_handler.LoginCustomer)

	// start the server at 8080
	e.Logger.Fatal(e.Start(":8080"))
}