package server

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"gsignver/internal/admin"
	"gsignver/internal/store"
)

type adminAppInfo struct {
	AppID             string `json:"app_id"`
	Name              string `json:"name"`
	MaxDevicesDefault int    `json:"max_devices_default"`
	LicenseTTLSeconds int64  `json:"license_ttl_seconds"`
	PublicKey         string `json:"public_key"`
}

func (s *Server) adminAuthed(r *http.Request) bool {
	if s.AdminToken == "" {
		return false
	}
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(s.AdminToken)) == 1
}

func writeAdminErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"code": status, "message": msg})
}

// handleAdminApps 处理 GET/POST /admin/v1/apps。
func (s *Server) handleAdminApps(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthed(r) {
		writeAdminErr(w, http.StatusUnauthorized, "未授权的管理请求")
		return
	}
	switch r.Method {
	case http.MethodGet:
		var apps []adminAppInfo
		err := s.repo.View(func(t *store.Tx) error {
			list, err := t.ListApps()
			if err != nil {
				return err
			}
			for _, a := range list {
				sk, _, ok, err := t.GetActiveSigningKey(a.AppID)
				if err != nil {
					return err
				}
				info := adminAppInfo{
					AppID: a.AppID, Name: a.Name,
					MaxDevicesDefault: a.MaxDevicesDefault,
					LicenseTTLSeconds: a.LicenseTTLSeconds,
				}
				if ok {
					info.PublicKey = sk.PublicKey
				}
				apps = append(apps, info)
			}
			return nil
		})
		if err != nil {
			writeAdminErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"apps": apps})

	case http.MethodPost:
		var req struct {
			AppID      string `json:"app_id"`
			Name       string `json:"name"`
			MaxDevices int    `json:"max_devices"`
			TTLSeconds int64  `json:"ttl_seconds"`
		}
		if err := decodeAdminBody(r, &req); err != nil {
			writeAdminErr(w, http.StatusBadRequest, err.Error())
			return
		}
		pub, err := admin.CreateApp(s.repo, s.kms, req.AppID, req.Name, req.MaxDevices, req.TTLSeconds)
		if err != nil {
			writeAdminErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"app_id": req.AppID, "public_key": pub})

	default:
		writeAdminErr(w, http.StatusMethodNotAllowed, "只接受 GET / POST")
	}
}

// handleAdminCodes 处理 POST /admin/v1/codes。
func (s *Server) handleAdminCodes(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthed(r) {
		writeAdminErr(w, http.StatusUnauthorized, "未授权的管理请求")
		return
	}
	if r.Method != http.MethodPost {
		writeAdminErr(w, http.StatusMethodNotAllowed, "只接受 POST")
		return
	}
	var req struct {
		AppID          string   `json:"app_id"`
		Edition        string   `json:"edition"`
		Features       []string `json:"features"`
		MaxDevices     int      `json:"max_devices"`
		CodeTTLSeconds int64    `json:"code_ttl_seconds"`
	}
	if err := decodeAdminBody(r, &req); err != nil {
		writeAdminErr(w, http.StatusBadRequest, err.Error())
		return
	}
	code, err := admin.IssueCode(s.repo, s.kms, req.AppID, req.Edition, req.Features, req.MaxDevices, req.CodeTTLSeconds)
	if err != nil {
		writeAdminErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"app_id": req.AppID, "activation_code": code,
		"edition": req.Edition, "max_devices": req.MaxDevices,
	})
}

func decodeAdminBody(r *http.Request, out any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}
