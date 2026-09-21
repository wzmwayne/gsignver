// Command gsigtest 是虚拟验证客户端：对运行中的服务端跑一遍协议场景，也可用作容器健康检查。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"gsignver/internal/client"
	"gsignver/internal/cryptox"
	"gsignver/internal/wire"
)

func main() {
	url := flag.String("url", envOr("GSIGTEST_URL", "http://127.0.0.1:8080"), "服务端基址（不含路径）")
	app := flag.String("app", os.Getenv("GSIGTEST_APP"), "app_id")
	pubB64 := flag.String("pub", os.Getenv("GSIGTEST_PUB"), "内置应用公钥（标准 Base64）")
	code := flag.String("code", os.Getenv("GSIGTEST_CODE"), "激活码")
	desc := flag.String("desc", "{\"name\":\"虚拟验证客户端\"}", "设备描述 JSON")
	healthOnly := flag.Bool("health", false, "仅探测健康检查端点")
	healthPath := flag.String("health-path", "/v1/health", "健康检查路径（相对 -url）")
	flag.Parse()

	if *healthOnly {
		if err := probe(*url + *healthPath); err != nil {
			fmt.Fprintln(os.Stderr, "health:", err)
			os.Exit(1)
		}
		return
	}
	if *app == "" || *pubB64 == "" || *code == "" {
		fmt.Fprintln(os.Stderr, "需要 -app、-pub、-code（或对应环境变量）")
		os.Exit(2)
	}
	pub, err := client.AppPubFromB64(*pubB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "解析应用公钥失败:", err)
		os.Exit(2)
	}
	c := client.New(*url, *app, pub)

	failed := 0
	check := func(name string, fn func() error) bool {
		if err := fn(); err != nil {
			failed++
			fmt.Printf("FAIL  %-30s %v\n", name, err)
			return false
		}
		fmt.Printf("PASS  %-30s\n", name)
		return true
	}

	if !check("激活", func() error {
		resp, err := c.Activate(*code, *desc)
		if err != nil {
			return err
		}
		if resp.License == nil {
			return errors.New("响应缺少 license")
		}
		return nil
	}) {
		fmt.Println("\n激活失败，后续场景无法进行")
		os.Exit(1)
	}

	check("列出设备", func() error {
		r, err := c.Biz(wire.BizRequest{Action: wire.ActionListDevices})
		if err != nil {
			return err
		}
		if r.Code != wire.CodeOK {
			return fmt.Errorf("code=%d %s", r.Code, r.Message)
		}
		for _, d := range r.Devices {
			if d.DeviceID == c.DeviceID {
				return nil
			}
		}
		return fmt.Errorf("设备列表中没有自己 %s", c.DeviceID)
	})

	check("刷新许可证", func() error {
		r, err := c.Biz(wire.BizRequest{Action: wire.ActionRefresh})
		if err != nil {
			return err
		}
		if r.Code != wire.CodeOK || r.License == nil {
			return fmt.Errorf("code=%d", r.Code)
		}
		return nil
	})

	check("负例: 篡改密文被拒", func() error {
		inner, _ := json.Marshal(wire.BizRequest{
			Action: wire.ActionListDevices, LicenseID: c.License.LicenseID,
			Nonce: "TAMPER-CT", TS: time.Now().Unix(),
		})
		ct, err := cryptox.AEADSeal(c.Key, inner)
		if err != nil {
			return err
		}
		ct[len(ct)-1] ^= 0xFF
		st, body := rawPost(*url+"/v1/biz", wire.Envelope{AppID: *app, DeviceID: c.DeviceID, Data: wire.B64(ct)})
		if st != 400 {
			return fmt.Errorf("期望 HTTP 400，得到 %d (%s)", st, body)
		}
		var be wire.BareError
		if err := json.Unmarshal(body, &be); err != nil {
			return err
		}
		if be.Code != wire.CodeCrypto {
			return fmt.Errorf("期望 code=%d，得到 %d", wire.CodeCrypto, be.Code)
		}
		return nil
	})

	check("负例: 业务 nonce 重放", func() error {
		inner, _ := json.Marshal(wire.BizRequest{
			Action: wire.ActionListDevices, LicenseID: c.License.LicenseID,
			Nonce: "REPLAY-FIXED-NONCE", TS: time.Now().Unix(),
		})
		ct, err := cryptox.AEADSeal(c.Key, inner)
		if err != nil {
			return err
		}
		env := wire.Envelope{AppID: *app, DeviceID: c.DeviceID, Data: wire.B64(ct)}
		if st, body := rawPost(*url+"/v1/biz", env); st != 200 {
			return fmt.Errorf("首次应 HTTP 200，得到 %d (%s)", st, body)
		}
		st, body := rawPost(*url+"/v1/biz", env)
		if st != 200 {
			return fmt.Errorf("重放应返回形态 A(HTTP 200)，得到 %d (%s)", st, body)
		}
		var oe wire.Envelope
		if err := json.Unmarshal(body, &oe); err != nil {
			return err
		}
		sealed, err := wire.UnB64(oe.Data)
		if err != nil {
			return err
		}
		plain, err := cryptox.AEADOpen(c.Key, sealed)
		if err != nil {
			return err
		}
		var r wire.BizResponse
		if err := json.Unmarshal(plain, &r); err != nil {
			return err
		}
		if r.Code != wire.CodeNonceReplay {
			return fmt.Errorf("期望 code=%d，得到 %d", wire.CodeNonceReplay, r.Code)
		}
		return nil
	})

	check("负例: 响应签名被篡改", func() error {
		pub2, err := client.AppPubFromB64(*pubB64)
		if err != nil {
			return err
		}
		c2 := client.New(*url, *app, pub2)
		c2.Now = c.Now
		c2.DeviceID = c.DeviceID
		c2.Key = c.Key
		c2.License = c.License
		c2.HTTP = &http.Client{Transport: tamper{}, Timeout: 10 * time.Second}
		_, err = c2.Biz(wire.BizRequest{Action: wire.ActionListDevices})
		if !errors.Is(err, client.ErrBadResponseSig) {
			return fmt.Errorf("期望 ErrBadResponseSig，得到 %v", err)
		}
		return nil
	})

	if failed > 0 {
		fmt.Printf("\n%d 个场景失败\n", failed)
		os.Exit(1)
	}
	fmt.Printf("\n全部场景通过\n")
}

// tamper 复写响应 JSON 中 data 的一个字符，破坏应用签名。
type tamper struct{}

func (tamper) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
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
	return resp, nil
}

func rawPost(url string, env wire.Envelope) (int, []byte) {
	b, _ := json.Marshal(env)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func probe(url string) error {
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
