package tests

import (
    "testing"
    "ftgo-finpro/config/database"
)

func TestMain(m *testing.M) {
    config.InitDB()
    defer config.CloseDB()

    // Run the tests
	m.Run()
}