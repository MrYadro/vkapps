// Package vkapps provides with some useful serverside functions for vkapps.
// More info about vkapps https://vk.com/dev/vk_apps_docs
package vkapps

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"sort"
	"strings"
)

// IsSignValid validates vk sign for provided vk launch parametres https://vk.com/dev/vk_apps_docs2?f=6.%2BLaunch%2BParameters
func IsSignValid(appURL, clientSecret string) (bool, error) {

	u, err := url.Parse(appURL)
	if err != nil {
		return false, err
	}

	query := u.RawQuery

	parsedQuery, err := url.ParseQuery(query)
	if err != nil {
		return false, err
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
	_, err = mac.Write([]byte(signParamQuery))
	if err != nil {
		return false, err
	}
	expectedMAC := mac.Sum(nil)

	baseEncoded := base64.StdEncoding.EncodeToString(expectedMAC)

	baseTrimmed := strings.TrimRight(baseEncoded, "=")

	replacer := strings.NewReplacer("+", "-", "/", "_")

	calculatedSign := replacer.Replace(baseTrimmed)

	return calculatedSign == expectedSign, nil
}
