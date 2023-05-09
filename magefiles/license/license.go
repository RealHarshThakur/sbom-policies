package license

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// Result is the result of the license check.
type Result struct {
	Deny               []Deny   `json:"deny"`
	ProhibitedLicenses []string `json:"prohibited_licenses"`
	ReviewLicenses     []string `json:"review_licenses"`
	Warn               []Warn   `json:"warn"`
}

// Deny contains denied packages.
type Deny struct {
	Package           string `json:"package"`
	ProhibitedLicense string `json:"prohibited_license"`
}

// Warn contains packages with licenses that need to be reviewed.
type Warn struct {
	Package       string `json:"package"`
	ReviewLicense string `json:"review_license"`
}

// Response is the result of the license check.
type Response struct {
	Result Result `json:"result"`
}

// Check sends a POST request to the OPA server to check the license.
func Check(url string, filename string) (*Response, error) {
	// Read JSON data from file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	requestBody := map[string]interface{}{
		"input": json.RawMessage(data),
	}

	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	// Create HTTP POST request
	request, err := http.NewRequest("POST", url, bytes.NewReader(requestBodyBytes))
	if err != nil {
		return nil, err
	}

	// Set content type header to JSON
	request.Header.Set("Content-Type", "application/json")

	// Send HTTP POST request
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Read response body
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	// Decode response JSON into struct
	var responseObject Response
	err = json.Unmarshal(responseBody, &responseObject)
	if err != nil {
		return nil, err
	}

	return &responseObject, nil
}
