package logger

import "log"

var isProduction = false

func SetProduction(prod bool) {
	isProduction = prod
}

func LogError(msg string, err error) {
	if !isProduction {
		if err != nil {
			log.Printf("[ERROR] %s: %v", msg, err)
		} else {
			log.Printf("[ERROR] %s", msg)
		}
	}
}

func LogInfo(msg string) {
	if !isProduction {
		log.Printf("[INFO] %s", msg)
	}
}
