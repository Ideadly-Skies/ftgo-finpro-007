package main
import (
	"ftgo-finpro/config/database"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main(){
	// migrate data to supabase
	config.MigrateData()

	// connect to db
	config.InitDB()
	defer config.CloseDB()
	
	// use echo-framework to simulate smart-city ecosystem
	e := echo.New()
	
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	
	// start the server at 8080
	e.Logger.Fatal(e.Start(":8080"))
}