// Package server 实现 HTTP 服务端：/v1/activate、/v1/biz、/v1/emergency/kickout。
package server

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"gsignver/internal/cryptox"
	"gsignver/internal/kms"
	"gsignver/internal/store"
	"gsignver/internal/wire"
)

// 服务端策略常量。
const (
	MaxBodyBytes    = 64 << 10
	DefaultTSWindow = 300 * time.Second
	DefaultNonceTTL = 10 * time.Minute
	rateMaxFailures = 10
	rateWindow      = time.Hour
	rateLock        = time.Hour
)

// Server 持有仓储与 KMS。
type Server struct {
	repo     *store.Repo
	kms      *kms.KMS
	TSWindow time.Duration
	NonceTTL time.Duration
	// AdminToken 非空时挂载 /admin/v1/* 管理接口（供服务运行期间签发激活码）。
	AdminToken string
	now        func() time.Time
}

// New 构造服务端。
func New(repo *store.Repo, k *kms.KMS) *Server {
	return &Server{repo: repo, kms: k, TSWindow: DefaultTSWindow, NonceTTL: DefaultNonceTTL, now: time.Now}
}

// SetClock 注入时钟（测试用）。
func (s *Server) SetClock(f func() time.Time) { s.now = f }

// KMS 暴露 KMS（运维子命令使用）。
func (s *Server) KMS() *kms.KMS { return s.kms }

// Repo 暴露仓储（运维子命令使用）。
func (s *Server) Repo() *store.Repo { return s.repo }

// Handler 返回路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/activate", s.handleActivate)
	mux.HandleFunc("/v1/biz", s.handleBiz)
	mux.HandleFunc("/v1/emergency/kickout", s.handleKickout)
	if s.AdminToken != "" {
		mux.HandleFunc("/admin/v1/apps", s.handleAdminApps)
		mux.HandleFunc("/admin/v1/codes", s.handleAdminCodes)
	}
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": "1.0"})
}

// readEnvelope 读取并校验外层信封；失败时已写出形态 B 响应。
func (s *Server) readEnvelope(w http.ResponseWriter, r *http.Request) (*wire.Envelope, bool) {
	if r.Method != http.MethodPost {
		writeBare(w, wire.Err(wire.CodeBadParam, "只接受 POST"))
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		writeBare(w, wire.Err(wire.CodeBadParam, "读取请求体失败"))
		return nil, false
	}
	if len(body) > MaxBodyBytes {
		writeBare(w, wire.Err(wire.CodeBodyTooLarge, "请求体超过 64 KiB"))
		return nil, false
	}
	var env wire.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeBare(w, wire.Err(wire.CodeBadParam, "请求体不是合法 JSON"))
		return nil, false
	}
	if env.AppID == "" || env.DeviceID == "" || env.Data == "" {
		writeBare(w, wire.Err(wire.CodeBadParam, "缺少必填外层字段 app_id/device_id/data"))
		return nil, false
	}
	return &env, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeEnvelope 写出形态 A 响应。
func writeEnvelope(w http.ResponseWriter, env wire.Envelope) {
	writeJSON(w, http.StatusOK, env)
}

// writeBare 写出形态 B（裸错误）响应。
func writeBare(w http.ResponseWriter, e *wire.Error) {
	writeJSON(w, wire.HTTPStatus(e.Code), wire.BareError{Code: e.Code, Message: e.Message})
}

// writeErr 把任意 error 归一后写出形态 B。
func (s *Server) writeErr(w http.ResponseWriter, err error) {
	writeBare(w, wire.AsError(err))
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func withinWindow(ts, now int64, window time.Duration) bool {
	d := now - ts
	if d < 0 {
		d = -d
	}
	return d <= int64(window/time.Second)
}

// isLocked 判断任一限流桶是否处于锁定状态。
func (s *Server) isLocked(buckets []string) (bool, error) {
	now := s.now().Unix()
	locked := false
	err := s.repo.View(func(t *store.Tx) error {
		for _, b := range buckets {
			rl, ok, err := t.GetRateLimit(b)
			if err != nil {
				return err
			}
			if ok && rl.LockedUntil > now {
				locked = true
				return nil
			}
		}
		return nil
	})
	return locked, err
}

// recordFailure 给每个桶累计一次失败，达到阈值即锁定。
func (s *Server) recordFailure(buckets []string) error {
	now := s.now().Unix()
	return s.repo.Update(func(t *store.Tx) error {
		for _, b := range buckets {
			rl, ok, err := t.GetRateLimit(b)
			if err != nil {
				return err
			}
			if !ok {
				rl = &store.RateLimit{WindowStart: now}
			}
			if now-rl.WindowStart > int64(rateWindow/time.Second) {
				rl.Failures = 0
				rl.WindowStart = now
				rl.LockedUntil = 0
			}
			rl.Failures++
			if rl.Failures >= rateMaxFailures {
				rl.LockedUntil = now + int64(rateLock/time.Second)
			}
			if err := t.PutRateLimit(b, rl); err != nil {
				return err
			}
		}
		return nil
	})
}

// clearFailures 成功时清空桶。
func (s *Server) clearFailures(buckets []string) {
	_ = s.repo.Update(func(t *store.Tx) error {
		for _, b := range buckets {
			t.DeleteRateLimit(b)
		}
		return nil
	})
}

// gate 执行限流检查；被锁则已写出 429。
func (s *Server) gate(w http.ResponseWriter, buckets []string) bool {
	locked, err := s.isLocked(buckets)
	if err != nil {
		s.writeErr(w, err)
		return false
	}
	if locked {
		writeBare(w, wire.Err(wire.CodeRateLimited, "请求过于频繁"))
		return false
	}
	return true
}

var errNoSigningKey = errors.New("server: app has no active signing key")

// signData 用应用的 active 签名私钥对 data 字符串签名。
func (s *Server) signData(t *store.Tx, appID, data string) (string, error) {
	_, sealed, ok, err := t.GetActiveSigningKey(appID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errNoSigningKey
	}
	seed, err := s.kms.Open(sealed)
	if err != nil {
		return "", err
	}
	return wire.SignData(cryptox.Ed25519FromSeed(seed), data), nil
}
