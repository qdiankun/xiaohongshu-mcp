package xiaohongshu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptchaSnapshotLifecycle(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("COOKIES_PATH", filepath.Join(dir, "cookies.json"))
	if err := os.MkdirAll(captchaDir(), 0o755); err != nil {
		t.Fatal(err)
	}

	// 无快照：nil, nil，取图接口据此返回"当前没有待处理验证码"
	snap, err := LoadCaptchaSnapshot()
	if err != nil || snap != nil {
		t.Fatalf("空快照应返回 (nil, nil)，得到 (%v, %v)", snap, err)
	}

	// 写入图片和元数据后可读出
	image := []byte("fake-png-bytes")
	if err := os.WriteFile(captchaImagePath(), image, 0o644); err != nil {
		t.Fatal(err)
	}
	meta := CaptchaSnapshot{
		Title:      "测试标题",
		DetectedAt: "2026-11-20T09:00:00+08:00",
		Reason:     "页面提示: 安全验证",
		ImagePath:  captchaImagePath(),
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(captchaMetaPath(), metaJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	snap, err = LoadCaptchaSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap == nil {
		t.Fatal("应读到快照")
	}
	if snap.Title != "测试标题" || snap.Reason == "" {
		t.Errorf("元数据不符: %+v", snap)
	}
	if snap.ImageBase64 == "" {
		t.Error("应带 base64 图片数据")
	}

	// 清除后回到无快照
	ClearCaptchaSnapshot()
	snap, err = LoadCaptchaSnapshot()
	if err != nil || snap != nil {
		t.Fatalf("清除后应为 (nil, nil)，得到 (%v, %v)", snap, err)
	}
}
