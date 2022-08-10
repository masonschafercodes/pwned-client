package pwnedclient

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	baseURL string = "https://haveibeenpwned.com/api/v2/"

	userAgent string = "pwned-go-client"
)

type PwnedClient struct {
	client    *http.Client
	UserAgent string
	BaseURL   *url.URL
}

func NewPwnedClient() *PwnedClient {
	baseURL, _ := url.Parse(baseURL)
	return &PwnedClient{
		client:    &http.Client{},
		UserAgent: userAgent,
		BaseURL:   baseURL,
	}
}

func (pc *PwnedClient) SetHTTPClient(client *http.Client) *PwnedClient {
	pc.client = client
	return pc
}

func (pc *PwnedClient) NewRequest(method, urlPath string, body interface{}) (*http.Request, error) {
	rel, err := url.Parse(urlPath)

	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)

	if body != nil {
		err = json.NewEncoder(buf).Encode(body)

		if err != nil {
			return nil, err
		}
	}

	request, err := http.NewRequest(method, pc.BaseURL.ResolveReference(rel).String(), buf)
	if err != nil {
		return nil, err
	}

	request.Header.Add("User-Agent", pc.UserAgent)

	return request, nil
}

func (pc *PwnedClient) Do(req *http.Request) ([]string, error) {

	response, err := pc.client.Do(req)

	if err != nil {
		return nil, err
	}

	defer func() {
		if responseerr := response.Body.Close(); err != nil {
			err = responseerr
		}
	}()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n"), err
}

func hashString(val string) string {
	alg := sha1.New()
	alg.Write([]byte(val))

	return strings.ToUpper(hex.EncodeToString(alg.Sum(nil)))
}

func (pc *PwnedClient) Compromissed(val string) (bool, error) {
	if val == "" {
		return false, errors.New("Empty Value")
	}

	hashedStr := hashString(val)
	prefix := strings.ToUpper(hashedStr[:5])
	suffix := strings.ToUpper(hashedStr[5:])

	request, err := pc.NewRequest("GET", fmt.Sprintf("range/%s", prefix), nil)

	if err != nil {
		return false, err
	}

	response, err := pc.Do(request)
	if err != nil {
		return false, err
	}

	for _, target := range response {
		if len(target) < 36 {
			continue
		}

		if target[:35] == suffix {
			if _, err = strconv.ParseInt(target[36:], 10, 64); err != nil {
				return false, err
			}

			return true, nil
		}
	}

	return false, nil
}

func (pc *PwnedClient) Breaches() ([]string, error) {
	request, err := pc.NewRequest("GET", "breaches", nil)

	if err != nil {
		return nil, err
	}

	response, err := pc.Do(request)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (pc *PwnedClient) BreachByDomain(domain_name string) ([]string, error) {
	request, err := pc.NewRequest("GET", fmt.Sprintf("breaches?domain=%s", domain_name), nil)

	if err != nil {
		return nil, err
	}

	response, err := pc.Do(request)
	if err != nil {
		return nil, err
	}

	return response, nil
}
