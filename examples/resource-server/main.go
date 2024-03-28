package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestDetails := map[string]string{
			"Method": r.Method,
			"Path":   r.URL.Path,
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			requestDetails["Authorization"] = authHeader
		}

		jsonDetails, err := json.Marshal(requestDetails)
		if err != nil {
			log.Printf("Error marshaling JSON: %v", err)
			return
		}

		log.Println(string(jsonDetails))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
