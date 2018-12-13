package vkapps

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net/url"
	"sort"
	"strings"
)

// IsSignValid validates vk sign for provided vk url https://vk.com/dev/vk_apps_docs?f=7.%2BLaunch%2BParameters
func IsSignValid(appURL, clientSecret string) (bool, error) {

	u, err := url.Parse(appURL)
	if err != nil {
		return false, err
	}

	query := u.RawQuery

	parsedQuery, err := url.ParseQuery(query)
	if err != nil {
		log.Fatal(err)
	}

	expectedSign := parsedQuery.Get("sign")

	keys := make([]string, 0, len(parsedQuery))
	for k := range parsedQuery {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	vkQuery := url.Values{}

	for _, k := range keys {
		if strings.HasPrefix(k, "vk_") {
			vkQuery[k] = parsedQuery[k]
		}
	}

	signParamQuery := vkQuery.Encode()

	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(signParamQuery))
	expectedMAC := mac.Sum(nil)

	baseEncoded := base64.StdEncoding.EncodeToString(expectedMAC)

	baseTrimmed := strings.TrimRight(baseEncoded, "=")

	replacer := strings.NewReplacer("+", "-", "/", "_")

	calculatedSign := replacer.Replace(baseTrimmed)

	return calculatedSign == expectedSign, nil
}
