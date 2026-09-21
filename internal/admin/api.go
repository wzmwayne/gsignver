package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// APIClient 通过运行中服务端的管理接口执行运维操作。
// 服务端持有数据目录的排他锁，因此不能在它运行时直接改文件。
type APIClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewAPIClient 构造管理接口客户端。
func NewAPIClient(baseURL, token string) *APIClient {
	return &APIClient{BaseURL: baseURL, Token: token, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *APIClient) do(method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var be struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(raw, &be); err == nil && be.Message != "" {
			return fmt.Errorf("管理接口 %d: %s", resp.StatusCode, be.Message)
		}
		return fmt.Errorf("管理接口返回 HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// CreateApp 远程创建应用。
func (c *APIClient) CreateApp(appID, name string, maxDevices int, ttlSeconds int64) (string, error) {
	var out struct {
		PublicKey string `json:"public_key"`
	}
	err := c.do(http.MethodPost, "/admin/v1/apps", map[string]any{
		"app_id": appID, "name": name,
		"max_devices": maxDevices, "ttl_seconds": ttlSeconds,
	}, &out)
	if err != nil {
		return "", err
	}
	if out.PublicKey == "" {
		return "", errors.New("admin: 管理接口未返回 public_key")
	}
	return out.PublicKey, nil
}

// IssueCode 远程签发激活码。
func (c *APIClient) IssueCode(appID, edition string, features []string, maxDevices int, codeTTLSeconds int64) (string, error) {
	var out struct {
		ActivationCode string `json:"activation_code"`
	}
	err := c.do(http.MethodPost, "/admin/v1/codes", map[string]any{
		"app_id": appID, "edition": edition, "features": features,
		"max_devices": maxDevices, "code_ttl_seconds": codeTTLSeconds,
	}, &out)
	if err != nil {
		return "", err
	}
	if out.ActivationCode == "" {
		return "", errors.New("admin: 管理接口未返回 activation_code")
	}
	return out.ActivationCode, nil
}

// ListApps 远程列出应用。
func (c *APIClient) ListApps() ([]string, error) {
	var out struct {
		Apps []struct {
			AppID             string `json:"app_id"`
			Name              string `json:"name"`
			MaxDevicesDefault int    `json:"max_devices_default"`
			LicenseTTLSeconds int64  `json:"license_ttl_seconds"`
			PublicKey         string `json:"public_key"`
		} `json:"apps"`
	}
	if err := c.do(http.MethodGet, "/admin/v1/apps", nil, &out); err != nil {
		return nil, err
	}
	list := make([]string, 0, len(out.Apps))
	for _, a := range out.Apps {
		list = append(list, fmt.Sprintf("%s	%s	max_devices=%d	ttl=%ds	pub=%s",
			a.AppID, a.Name, a.MaxDevicesDefault, a.LicenseTTLSeconds, a.PublicKey))
	}
	return list, nil
}
