package config

import (
	"context"
	"fmt"
	"log"
	"time"
	"io/ioutil"
	"os"
	"strings"
	"github.com/joho/godotenv"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var Pool *pgxpool.Pool

func InitDB(){
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Retrieve DIRECT_URL from .env
	directURL := os.Getenv("DIRECT_URL")
	
	if directURL == "" {
		log.Fatalf("Environment variable DIRECT_URL is not set")
	}	

	// Parse the config
	config, err := pgxpool.ParseConfig(directURL)
	if err != nil {
		log.Fatalf("Failed to parse DB config: %v", err)
	}

    if err != nil {
        log.Fatalf("Failed to parsing config DB: %v", err)
    }
	
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	
	// Add AfterConnect to clean up prepared statements or session state
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		// Discard all session-level state, including prepared statements
		_, err := conn.Exec(ctx, "DISCARD ALL")
		if err != nil {
			fmt.Printf("Error during AfterConnect: %v\n", err)
		}
		return err
	}
	
	// create db pooling
	Pool, err = pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
        log.Fatalf("Failed to create db pooling: %v", err)
    }

    err = Pool.Ping(context.Background())
    
	if err != nil {
        log.Fatalf("DB failed Ping: %v", err)
    }

	fmt.Println("Database connected")
}

func MigrateData(){
	// use recover to handle any potential panics
	defer HandlePanic()
	
	// create a context with a timeout (e.g., 30 seconds)
	ctx, cancel := context.WithTimeout(context.Background(), 30_000_000_000)
	defer cancel()

	// read the filename from the first argument
	filename := "config/database/ddl.sql"
	
	// read SQL commands from the file with the given filename
	sqlCommands, err := ReadSQLCommands(filename)
	
	// connect to the DB
	InitDB();
	
	if err != nil {
		panic(err)
	}
	
	defer CloseDB();
	
	// execute SQL commands
	err = ExecuteSQLCommands(ctx, Pool, sqlCommands)
	if err != nil {
		panic(err)
	}
	
	// output successful table creation and population
	fmt.Println("All Tables Created and Populated Successfully!")
}

// func to handle panic using recover
func HandlePanic(){
	if r := recover(); r != nil {
		fmt.Println("Recovered from panic", r)
	}
}

// function to read SQL commands from a file
func ReadSQLCommands(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// function to execute SQL commands on the db
func ExecuteSQLCommands(ctx context.Context, db *pgxpool.Pool, commands string) error {
	statements := strings.Split(commands, ";") // split SQL commands by semicolon
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)		   // Trim whitespace
		if stmt != "" {
			_, err := db.Exec(ctx, stmt)
			if err != nil {
				return fmt.Errorf("failed to execute statement %q: %w", stmt, err)
			}
		}
	}
	return nil
}

func CloseDB() {
    Pool.Close()
}

func ResetDB() {
    if Pool != nil {
        fmt.Println("Resetting the database connection pool...")
        Pool.Close()
    }
    InitDB() // Reinitialize the pool
}