package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/matthogan/licenceserver/internal/admintransport"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/security"
)

type Client struct {
	BaseURL         string
	HTTP            *http.Client
	DownloadTimeout time.Duration
}
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s (request %s)", e.Code, e.Message, e.RequestID)
}
func New(url string) *Client {
	return &Client{BaseURL: strings.TrimRight(url, "/"), HTTP: &http.Client{Timeout: 20 * time.Second}, DownloadTimeout: 10 * time.Minute}
}
func NewForConfig(c config.Config) (*Client, error) {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}
	baseURL := strings.TrimRight(c.Admin.URL, "/")
	switch c.Admin.Transport {
	case "unix":
		transport.Proxy = nil
		transport.DialContext = admintransport.DialContext("unix", c.Admin.Socket)
		baseURL = "http://licd"
	case "named_pipe":
		transport.Proxy = nil
		transport.DialContext = admintransport.DialContext("named_pipe", c.Admin.Pipe)
		baseURL = "http://licd"
	case "tcp":
		parsed, err := url.Parse(baseURL)
		if err != nil {
			return nil, err
		}
		if parsed.Scheme == "https" {
			tlsConfig, err := security.AdminClientTLSConfig(c)
			if err != nil {
				return nil, err
			}
			transport.TLSClientConfig = tlsConfig
		} else if parsed.Scheme != "http" {
			return nil, fmt.Errorf("admin URL scheme must be http or https")
		}
	default:
		return nil, fmt.Errorf("unsupported admin transport %q", c.Admin.Transport)
	}
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 20 * time.Second, Transport: transport}, DownloadTimeout: 10 * time.Minute}, nil
}
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	return c.DoHeaders(ctx, method, path, body, out, nil)
}

func (c *Client) DoHeaders(ctx context.Context, method, path string, body, out any, headers map[string]string) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 2<<20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope struct {
			Error struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		if err = json.NewDecoder(limited).Decode(&envelope); err != nil {
			return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message, RequestID: envelope.Error.RequestID}
	}
	if out == nil {
		_, err = io.Copy(io.Discard, limited)
		return err
	}
	if err = json.NewDecoder(limited).Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// Download sends a JSON request and copies a successful response without the
// normal small JSON-response limit. The caller owns exclusive output and size
// policy. Error envelopes remain bounded and typed.
func (c *Client) Download(ctx context.Context, method, path string, body any, destination io.Writer) (http.Header, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	httpClient := *c.HTTP
	if c.DownloadTimeout > 0 {
		httpClient.Timeout = c.DownloadTimeout
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Error struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		if err = json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&envelope); err != nil {
			return nil, fmt.Errorf("server returned HTTP %d", response.StatusCode)
		}
		return nil, &APIError{Status: response.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message, RequestID: envelope.Error.RequestID}
	}
	if destination == nil {
		return nil, errors.New("download destination is required")
	}
	if _, err = io.Copy(destination, response.Body); err != nil {
		return nil, err
	}
	return response.Header.Clone(), nil
}
