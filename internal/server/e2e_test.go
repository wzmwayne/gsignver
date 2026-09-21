package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gsignver/internal/admin"
	"gsignver/internal/client"
	"gsignver/internal/cryptox"
	"gsignver/internal/kms"
	"gsignver/internal/kv"
	"gsignver/internal/server"
	"gsignver/internal/store"
	"gsignver/internal/wire"
)

type harness struct {
	ts    *httptest.Server
	srv   *server.Server
	repo  *store.Repo
	kms   *kms.KMS
	appID string
	pub   string
	now   time.Time
}

func newHarness(t *testing.T) *harness { return newHarnessWithAdmin(t, "") }

func newHarnessWithAdmin(t *testing.T, adminToken string) *harness {
	t.Helper()
	dir := t.TempDir()
	db, err := kv.Open(dir + "/kv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	km, err := kms.Open(dir + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	repo := store.New(db)
	h := &harness{srv: server.New(repo, km), repo: repo, kms: km, appID: "com.example.app", now: time.Unix(1710000000, 0)}
	h.srv.SetClock(func() time.Time { return h.now })
	pub, err := admin.CreateApp(repo, km, h.appID, "示例应用", 3, 30*24*3600)
	if err != nil {
		t.Fatal(err)
	}
	h.pub = pub
	h.srv.AdminToken = adminToken
	h.ts = httptest.NewServer(h.srv.Handler())
	t.Cleanup(h.ts.Close)
	return h
}

func (h *harness) issue(t *testing.T, maxDevices int) string {
	t.Helper()
	code, err := admin.IssueCode(h.repo, h.kms, h.appID, "pro", []string{"export"}, maxDevices, 0)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func (h *harness) newClient(t *testing.T) *client.Client {
	t.Helper()
	pub, err := client.AppPubFromB64(h.pub)
	if err != nil {
		t.Fatal(err)
	}
	c := client.New(h.ts.URL, h.appID, pub)
	c.Now = func() time.Time { return h.now }
	return c
}

func postRaw(t *testing.T, url string, env wire.Envelope) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func bareCode(t *testing.T, body []byte) int {
	t.Helper()
	var be wire.BareError
	if err := json.Unmarshal(body, &be); err != nil {
		t.Fatalf("响应不是形态 B: %s", body)
	}
	return be.Code
}

func TestActivateHappyPath(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	c := h.newClient(t)
	resp, err := c.Activate(code, `{"name":"PC"}`)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != wire.CodeOK || resp.DeviceID == "" {
		t.Fatalf("bad activate response: %+v", resp)
	}
	if len(c.Key) != cryptox.KeyLen {
		t.Fatalf("K 长度 %d", len(c.Key))
	}
	if resp.License.AppID != h.appID || resp.License.DeviceID != resp.DeviceID {
		t.Fatalf("license 不匹配: %+v", resp.License)
	}
	if resp.License.ExpiresAt != h.now.Unix()+30*24*3600 {
		t.Fatalf("expires_at = %d", resp.License.ExpiresAt)
	}
	r, err := c.Biz(wire.BizRequest{Action: wire.ActionListDevices})
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != wire.CodeOK || r.MaxDevices != 3 || len(r.Devices) != 1 {
		t.Fatalf("list_devices: %+v", r)
	}
}

func postActivateErr(t *testing.T, h *harness, code string) (int, []byte) {
	t.Helper()
	priv, err := cryptox.X25519Generate()
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := cryptox.Random(16)
	inner, _ := json.Marshal(wire.ActivateRequest{
		Action: wire.ActionActivate, ActivationCode: code,
		DeviceDesc: wire.B64([]byte("d")), DeviceEncPub: wire.B64(priv.PublicKey().Bytes()),
		Nonce: wire.B64URL(nonce), TS: h.now.Unix(),
	})
	return postRaw(t, h.ts.URL+"/v1/activate", wire.Envelope{
		AppID: h.appID, DeviceID: wire.DeviceAnonymous, Data: wire.B64(inner),
	})
}

func TestDeviceLimitAndNoDeviceList(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	for i := 0; i < 3; i++ {
		c := h.newClient(t)
		if _, err := c.Activate(code, "d"); err != nil {
			t.Fatalf("第 %d 台激活失败: %v", i+1, err)
		}
	}
	st, body := postActivateErr(t, h, code)
	if st != 400 || bareCode(t, body) != wire.CodeDeviceLimit {
		t.Fatalf("第 4 台应当 %d: %d %s", wire.CodeDeviceLimit, st, body)
	}
	if bytes.Contains(body, []byte("devices")) {
		t.Fatalf("2003 响应不应包含设备列表: %s", body)
	}
}

func TestEmergencyKickoutFreesSlot(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 1)
	c1 := h.newClient(t)
	if _, err := c1.Activate(code, "first"); err != nil {
		t.Fatal(err)
	}
	if st, body := postActivateErr(t, h, code); bareCode(t, body) != wire.CodeDeviceLimit {
		t.Fatalf("期望 %d: %d %s", wire.CodeDeviceLimit, st, body)
	}
	c2 := h.newClient(t)
	ko, err := c2.Kickout(code)
	if err != nil {
		t.Fatal(err)
	}
	if ko.KickedDeviceID != c1.DeviceID {
		t.Fatalf("踢出 %s，期望 %s", ko.KickedDeviceID, c1.DeviceID)
	}
	if _, err := c2.Activate(code, "second"); err != nil {
		t.Fatalf("踢出后激活失败: %v", err)
	}
	if _, err := c1.Biz(wire.BizRequest{Action: wire.ActionListDevices}); err == nil {
		t.Fatal("被踢设备仍能发业务请求")
	} else if we, ok := err.(*wire.Error); !ok || we.Code != wire.CodeCrypto {
		t.Fatalf("被踢设备错误 = %v，期望 %d", err, wire.CodeCrypto)
	}
}

func TestRepeatActivateCreatesNewIdentity(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	c1 := h.newClient(t)
	r1, err := c1.Activate(code, "a")
	if err != nil {
		t.Fatal(err)
	}
	c2 := h.newClient(t)
	r2, err := c2.Activate(code, "b")
	if err != nil {
		t.Fatal(err)
	}
	if r1.DeviceID == r2.DeviceID {
		t.Fatal("重复激活应当产生新身份")
	}
	if bytes.Equal(c1.Key, c2.Key) {
		t.Fatal("重复激活应当产生新 K")
	}
}

func TestActivationErrors(t *testing.T) {
	h := newHarness(t)
	c := h.newClient(t)
	if _, err := c.Activate("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "x"); err == nil {
		t.Fatal("不存在的激活码应当失败")
	} else if we, ok := err.(*wire.Error); !ok || we.Code != wire.CodeActivationBad {
		t.Fatalf("期望 %d，得到 %v", wire.CodeActivationBad, err)
	}
	bad := h.newClient(t)
	bad.Now = func() time.Time { return h.now.Add(10 * time.Minute) }
	if _, err := bad.Activate(h.issue(t, 3), "x"); err == nil {
		t.Fatal("越窗时间戳应当失败")
	} else if we, ok := err.(*wire.Error); !ok || we.Code != wire.CodeTimestampStale {
		t.Fatalf("期望 %d，得到 %v", wire.CodeTimestampStale, err)
	}
	pub, _ := client.AppPubFromB64(h.pub)
	other := client.New(h.ts.URL, "com.other.app", pub)
	other.Now = func() time.Time { return h.now }
	if _, err := other.Activate(h.issue(t, 3), "x"); err == nil {
		t.Fatal("未知 app_id 应当失败")
	} else if we, ok := err.(*wire.Error); !ok || we.Code != wire.CodeAppNotFound {
		t.Fatalf("期望 %d，得到 %v", wire.CodeAppNotFound, err)
	}
}

func TestActivateNonceReplay(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	priv, _ := cryptox.X25519Generate()
	nonce, _ := cryptox.Random(16)
	inner, _ := json.Marshal(wire.ActivateRequest{
		Action: wire.ActionActivate, ActivationCode: code, DeviceDesc: wire.B64([]byte("d")),
		DeviceEncPub: wire.B64(priv.PublicKey().Bytes()), Nonce: wire.B64URL(nonce), TS: h.now.Unix(),
	})
	env := wire.Envelope{AppID: h.appID, DeviceID: wire.DeviceAnonymous, Data: wire.B64(inner)}
	if st, body := postRaw(t, h.ts.URL+"/v1/activate", env); st != 200 {
		t.Fatalf("首次应成功: %d %s", st, body)
	}
	st, body := postRaw(t, h.ts.URL+"/v1/activate", env)
	if st != 400 || bareCode(t, body) != wire.CodeNonceReplay {
		t.Fatalf("重放应当 %d: %d %s", wire.CodeNonceReplay, st, body)
	}
}

func TestBizNonceReplayIsShapeA(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	c := h.newClient(t)
	if _, err := c.Activate(code, "d"); err != nil {
		t.Fatal(err)
	}
	inner, _ := json.Marshal(wire.BizRequest{
		Action: wire.ActionListDevices, LicenseID: c.License.LicenseID,
		Nonce: "AAAAAAAAAAAAAAAAAAAAAA", TS: h.now.Unix(),
	})
	ct, _ := cryptox.AEADSeal(c.Key, inner)
	env := wire.Envelope{AppID: h.appID, DeviceID: c.DeviceID, Data: wire.B64(ct)}
	if st, body := postRaw(t, h.ts.URL+"/v1/biz", env); st != 200 {
		t.Fatalf("首次应成功: %d %s", st, body)
	}
	st, body := postRaw(t, h.ts.URL+"/v1/biz", env)
	if st != 200 {
		t.Fatalf("重放应当是形态 A(HTTP 200)，得到 %d %s", st, body)
	}
	var outEnv wire.Envelope
	if err := json.Unmarshal(body, &outEnv); err != nil {
		t.Fatal(err)
	}
	sealed, err := wire.UnB64(outEnv.Data)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cryptox.AEADOpen(c.Key, sealed)
	if err != nil {
		t.Fatal(err)
	}
	var r wire.BizResponse
	if err := json.Unmarshal(plain, &r); err != nil {
		t.Fatal(err)
	}
	if r.Code != wire.CodeNonceReplay {
		t.Fatalf("期望 %d，得到 %+v", wire.CodeNonceReplay, r)
	}
}

func TestBizTamperedCiphertext(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	c := h.newClient(t)
	if _, err := c.Activate(code, "d"); err != nil {
		t.Fatal(err)
	}
	inner, _ := json.Marshal(wire.BizRequest{Action: wire.ActionListDevices, LicenseID: c.License.LicenseID, Nonce: "N1", TS: h.now.Unix()})
	ct, _ := cryptox.AEADSeal(c.Key, inner)
	ct[len(ct)-1] ^= 0xFF
	st, body := postRaw(t, h.ts.URL+"/v1/biz", wire.Envelope{AppID: h.appID, DeviceID: c.DeviceID, Data: wire.B64(ct)})
	if st != 400 || bareCode(t, body) != wire.CodeCrypto {
		t.Fatalf("篡改密文应当 %d: %d %s", wire.CodeCrypto, st, body)
	}
}

func TestBizUnknownDevice(t *testing.T) {
	h := newHarness(t)
	st, body := postRaw(t, h.ts.URL+"/v1/biz", wire.Envelope{
		AppID: h.appID, DeviceID: "srv_UNKNOWN", Data: wire.B64([]byte("whatever")),
	})
	if st != 400 || bareCode(t, body) != wire.CodeCrypto {
		t.Fatalf("未知设备应当 %d: %d %s", wire.CodeCrypto, st, body)
	}
}

func TestRemoveSelfThenBizFails(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	c := h.newClient(t)
	if _, err := c.Activate(code, "d"); err != nil {
		t.Fatal(err)
	}
	r, err := c.Biz(wire.BizRequest{Action: wire.ActionRemoveDevice, TargetDeviceID: c.DeviceID})
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != wire.CodeOK || r.RemovedID != c.DeviceID {
		t.Fatalf("remove_device: %+v", r)
	}
	if _, err := c.Biz(wire.BizRequest{Action: wire.ActionListDevices}); err == nil {
		t.Fatal("已删除设备仍可发业务请求")
	}
}

func TestRefreshRenewsLicense(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	c := h.newClient(t)
	if _, err := c.Activate(code, "d"); err != nil {
		t.Fatal(err)
	}
	old := c.License.ExpiresAt
	h.now = h.now.Add(24 * time.Hour)
	r, err := c.Biz(wire.BizRequest{Action: wire.ActionRefresh})
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != wire.CodeOK || r.License == nil {
		t.Fatalf("refresh: %+v", r)
	}
	if r.License.ExpiresAt <= old {
		t.Fatalf("refresh 未续期: %d -> %d", old, r.License.ExpiresAt)
	}
}

func TestBodyTooLarge(t *testing.T) {
	h := newHarness(t)
	big := bytes.Repeat([]byte("a"), server.MaxBodyBytes+10)
	resp, err := http.Post(h.ts.URL+"/v1/activate", "application/json", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 400 || bareCode(t, body) != wire.CodeBodyTooLarge {
		t.Fatalf("期望 %d: %d %s", wire.CodeBodyTooLarge, resp.StatusCode, body)
	}
}

func TestBadDeviceDesc(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	priv, _ := cryptox.X25519Generate()
	nonce, _ := cryptox.Random(16)
	inner, _ := json.Marshal(wire.ActivateRequest{
		Action: wire.ActionActivate, ActivationCode: code, DeviceDesc: "!!!not-base64!!!",
		DeviceEncPub: wire.B64(priv.PublicKey().Bytes()), Nonce: wire.B64URL(nonce), TS: h.now.Unix(),
	})
	st, body := postRaw(t, h.ts.URL+"/v1/activate", wire.Envelope{AppID: h.appID, DeviceID: wire.DeviceAnonymous, Data: wire.B64(inner)})
	if st != 400 || bareCode(t, body) != wire.CodeBadParam {
		t.Fatalf("非法 device_desc 应当 %d: %d %s", wire.CodeBadParam, st, body)
	}
}

func TestConcurrentQuota(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, limited := 0, 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, body := postActivateErr(t, h, code)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case st == 200:
				ok++
			case bareCode(t, body) == wire.CodeDeviceLimit:
				limited++
			}
		}()
	}
	wg.Wait()
	var total int
	if err := h.repo.View(func(tx *store.Tx) error { total = tx.CountAllDevices(); return nil }); err != nil {
		t.Fatal(err)
	}
	if total != 1 || ok != 1 {
		t.Fatalf("并发配额被突破: 成功 %d，设备行数 %d，受限 %d", ok, total, limited)
	}
}

func TestRateLimitLocks(t *testing.T) {
	h := newHarness(t)
	c := h.newClient(t)
	last := 0
	for i := 0; i < 12; i++ {
		_, err := c.Activate("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "x")
		we, ok := err.(*wire.Error)
		if !ok {
			t.Fatalf("第 %d 次: %v", i, err)
		}
		last = we.Code
	}
	if last != wire.CodeRateLimited {
		t.Fatalf("期望最终被限流 %d，得到 %d", wire.CodeRateLimited, last)
	}
}

func TestAppSigTamperRejected(t *testing.T) {
	h := newHarness(t)
	code := h.issue(t, 3)
	pub, _ := client.AppPubFromB64(h.pub)
	c := client.New(h.ts.URL, h.appID, pub)
	c.Now = func() time.Time { return h.now }
	c.HTTP = &http.Client{Transport: tamperTransport{base: http.DefaultTransport}}
	if _, err := c.Activate(code, "d"); err != client.ErrBadResponseSig {
		t.Fatalf("篡改响应应当被拒绝，得到 %v", err)
	}
}

type tamperTransport struct{ base http.RoundTripper }

func (tt tamperTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := tt.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err == nil {
		if d, ok := env["data"].(string); ok && len(d) > 10 {
			b := []byte(d)
			if b[5] == 'A' {
				b[5] = 'B'
			} else {
				b[5] = 'A'
			}
			env["data"] = string(b)
			body, _ = json.Marshal(env)
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

func TestAdminAPI(t *testing.T) {
	const token = "secret-admin-token"
	h := newHarnessWithAdmin(t, token)

	// 未授权
	resp, err := http.Post(h.ts.URL+"/admin/v1/codes", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，得到 %d", resp.StatusCode)
	}

	// 错误令牌
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/admin/v1/codes", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer wrong")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误令牌应 401，得到 %d", r2.StatusCode)
	}

	// 正确令牌签发激活码
	ac := admin.NewAPIClient(h.ts.URL, token)
	code, err := ac.IssueCode(h.appID, "pro", []string{"export"}, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code == "" {
		t.Fatal("未返回激活码")
	}
	// 列应用
	list, err := ac.ListApps()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || !strings.Contains(list[0], h.pub) {
		t.Fatalf("ListApps = %v", list)
	}
	// 服务端运行期间也能签发 -> 立刻可用
	c := h.newClient(t)
	if _, err := c.Activate(code, "via-admin"); err != nil {
		t.Fatalf("用管理接口签发的码激活失败: %v", err)
	}

	// 未挂载管理接口时路径不存在
	h2 := newHarness(t)
	resp3, err := http.Post(h2.ts.URL+"/admin/v1/codes", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("未启用管理接口应 404，得到 %d", resp3.StatusCode)
	}
}

func TestHealth(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.ts.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health status %d", resp.StatusCode)
	}
}
