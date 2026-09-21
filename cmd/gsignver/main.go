// Command gsignver 是激活码服务的可执行入口。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gsignver/internal/admin"
	"gsignver/internal/kms"
	"gsignver/internal/kv"
	"gsignver/internal/server"
	"gsignver/internal/store"
)

// version 可在构建时通过 -ldflags 覆盖。
var version = "1.0.0"

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "init":
		err = cmdInit(os.Args[2:])
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "apps":
		err = cmdApps(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("gsignver", version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("gsignver: %v", err)
	}
}

func usage() {
	w := os.Stderr
	for _, line := range []string{
		"gsignver " + version + " - 通用软件激活码服务端",
		"",
		"用法:",
		"  gsignver serve   启动 HTTP 服务",
		"  gsignver init    创建/更新应用并生成应用签名密钥",
		"  gsignver issue   签发一枚激活码（明文仅打印一次）",
		"  gsignver apps    列出全部应用",
		"  gsignver version 打印版本",
		"",
		"通用环境变量（命令行参数优先）:",
		"  GSIGNVER_DATA   数据目录，默认 ./data",
		"  GSIGNVER_ADDR   监听地址，默认 :8080",
		"",
		"示例:",
		"  gsignver init  -app com.example.app -name 示例 -max-devices 3",
		"  gsignver issue -app com.example.app -edition pro -features export,api",
		"  gsignver serve",
	} {
		fmt.Fprintln(w, line)
	}
}

func dataDir() string {
	if v := os.Getenv("GSIGNVER_DATA"); v != "" {
		return v
	}
	return "./data"
}

// openStore 打开 KV 与 KMS。落盘默认加密，密钥由 master key 经 HKDF 派生；
// 设置 GSIGNVER_ENCRYPT=0 可关闭（仅用于排障）。
func openStore(dir string) (*store.Repo, *kms.KMS, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	km, err := kms.Open(filepath.Join(dir, "keys"))
	if err != nil {
		return nil, nil, err
	}
	var opts []kv.Option
	if os.Getenv("GSIGNVER_ENCRYPT") != "0" {
		k, err := km.DeriveKey("gsignver/kv/v1", 32)
		if err != nil {
			return nil, nil, err
		}
		c, err := kv.NewAESGCMCipher(k)
		if err != nil {
			return nil, nil, err
		}
		opts = append(opts, kv.WithCipher(c))
	}
	db, err := kv.Open(filepath.Join(dir, "kv"), opts...)
	if err != nil {
		return nil, nil, err
	}
	return store.New(db), km, nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := fs.String("data", dataDir(), "数据目录")
	addr := fs.String("addr", envOr("GSIGNVER_ADDR", ":8080"), "监听地址")
	pruneEvery := fs.Duration("prune", 10*time.Minute, "过期 nonce 清理周期，0 表示关闭")
	if err := fs.Parse(args); err != nil {
		return err
	}

	repo, km, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer repo.Close()

	srv := server.New(repo, km)
	srv.AdminToken = os.Getenv("GSIGNVER_ADMIN_TOKEN")
	if srv.AdminToken != "" {
		log.Println("管理接口已启用: /admin/v1/*")
	}
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *pruneEvery > 0 {
		go func() {
			t := time.NewTicker(*pruneEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := repo.PruneExpired(time.Now().Unix()); err != nil {
						log.Printf("清理 nonce 失败: %v", err)
					}
				}
			}
		}()
	}

	errc := make(chan error, 1)
	go func() {
		log.Printf("gsignver %s 监听 %s，数据目录 %s", version, *addr, *dir)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Println("收到退出信号，正在优雅关闭")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("data", dataDir(), "数据目录")
	app := fs.String("app", "", "应用 app_id（必填）")
	name := fs.String("name", "", "应用名称")
	maxDevices := fs.Int("max-devices", 1, "默认设备上限")
	ttl := fs.Int64("ttl", 30*24*3600, "许可证有效期（秒）")
	adminURL := fs.String("admin-url", envOr("GSIGNVER_ADMIN_URL", ""), "管理接口地址；设置后对运行中的服务端操作")
	adminToken := fs.String("admin-token", envOr("GSIGNVER_ADMIN_TOKEN", ""), "管理接口令牌")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *app == "" {
		return errors.New("必须提供 -app")
	}
	if *adminURL != "" {
		pub, err := admin.NewAPIClient(*adminURL, *adminToken).CreateApp(*app, *name, *maxDevices, *ttl)
		if err != nil {
			return err
		}
		fmt.Printf("应用已就绪: %s\n", *app)
		fmt.Printf("客户端内置应用公钥(标准 Base64): %s\n", pub)
		return nil
	}
	repo, km, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer repo.Close()
	pub, err := admin.CreateApp(repo, km, *app, *name, *maxDevices, *ttl)
	if err != nil {
		return err
	}
	fmt.Printf("应用已就绪: %s\n", *app)
	fmt.Printf("客户端内置应用公钥(标准 Base64): %s\n", pub)
	return nil
}

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	dir := fs.String("data", dataDir(), "数据目录")
	app := fs.String("app", "", "应用 app_id（必填）")
	edition := fs.String("edition", "pro", "版本标识")
	features := fs.String("features", "", "功能列表，逗号分隔")
	maxDevices := fs.Int("max-devices", 0, "设备上限，0 表示用应用默认值")
	codeTTL := fs.Int64("code-ttl", 0, "激活码自身有效期（秒），0 表示永久")
	adminURL := fs.String("admin-url", envOr("GSIGNVER_ADMIN_URL", ""), "管理接口地址；设置后对运行中的服务端操作")
	adminToken := fs.String("admin-token", envOr("GSIGNVER_ADMIN_TOKEN", ""), "管理接口令牌")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *app == "" {
		return errors.New("必须提供 -app")
	}
	var feats []string
	for _, f := range strings.Split(*features, ",") {
		if f = strings.TrimSpace(f); f != "" {
			feats = append(feats, f)
		}
	}
	if *adminURL != "" {
		code, err := admin.NewAPIClient(*adminURL, *adminToken).IssueCode(*app, *edition, feats, *maxDevices, *codeTTL)
		if err != nil {
			return err
		}
		fmt.Printf("激活码（仅此一次可见，请立即保存）:\n%s\n", code)
		return nil
	}
	repo, km, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer repo.Close()
	code, err := admin.IssueCode(repo, km, *app, *edition, feats, *maxDevices, *codeTTL)
	if err != nil {
		return err
	}
	fmt.Printf("激活码（仅此一次可见，请立即保存）:\n%s\n", code)
	return nil
}

func cmdApps(args []string) error {
	fs := flag.NewFlagSet("apps", flag.ExitOnError)
	dir := fs.String("data", dataDir(), "数据目录")
	adminURL := fs.String("admin-url", envOr("GSIGNVER_ADMIN_URL", ""), "管理接口地址；设置后对运行中的服务端操作")
	adminToken := fs.String("admin-token", envOr("GSIGNVER_ADMIN_TOKEN", ""), "管理接口令牌")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *adminURL != "" {
		list, err := admin.NewAPIClient(*adminURL, *adminToken).ListApps()
		if err != nil {
			return err
		}
		printApps(list)
		return nil
	}
	repo, _, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer repo.Close()
	list, err := admin.ListApps(repo)
	if err != nil {
		return err
	}
	printApps(list)
	return nil
}

func printApps(list []string) {
	if len(list) == 0 {
		fmt.Println("(暂无应用)")
		return
	}
	for _, l := range list {
		fmt.Println(l)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
