package xiaohongshu

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/go-rod/rod"
	"github.com/xpzouying/xiaohongshu-mcp/cookies"
)

// 验证码快照落盘位置：跟 cookies 同目录（容器里是 /app/data，挂载卷内，重启不丢）。
const (
	captchaMetaFile  = "captcha.json"
	captchaImageFile = "captcha.png"
)

// CaptchaSnapshot 一次验证码现场。
type CaptchaSnapshot struct {
	Title       string `json:"title"`
	DetectedAt  string `json:"detected_at"`
	Reason      string `json:"reason"`
	ImagePath   string `json:"image_path"`
	ImageBase64 string `json:"image_base64,omitempty"`
}

func captchaDir() string {
	return filepath.Join(filepath.Dir(cookies.GetCookiesFilePath()), "captcha")
}

func captchaMetaPath() string  { return filepath.Join(captchaDir(), captchaMetaFile) }
func captchaImagePath() string { return filepath.Join(captchaDir(), captchaImageFile) }

// jsDetectCaptcha 识别发布过程中的验证码：带验证码特征的 iframe，或页面上的验证提示文案。
// 空 src 的普通 iframe 不算——发布页常年挂着这种框架，误判会打断正常发布。
const jsDetectCaptcha = `() => {
  const visible = el => {
    if (!el || el.nodeType !== 1) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 20 || r.height < 20) return false;
    const s = getComputedStyle(el);
    return s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0';
  };
  const frames = Array.from(document.querySelectorAll('iframe')).filter(visible);
  for (const f of frames) {
    const src = (f.getAttribute('src') || '').toLowerCase();
    if (/captcha|verify|geetest|challenge|secur/.test(src)) {
      return '验证码框架: ' + src.slice(0, 120);
    }
  }
  const keys = ['安全验证', '请完成验证', '滑动验证', '滑块验证', '输入验证码', '图形验证码', '点选验证', 'captcha', 'geetest'];
  const nodes = Array.from(document.querySelectorAll('div, span, p, button'));
  for (const el of nodes) {
    if (!visible(el)) continue;
    const t = (el.textContent || '').trim();
    if (t.length === 0 || t.length > 40) continue;
    for (const k of keys) {
      if (t.toLowerCase().includes(k.toLowerCase())) return '页面提示: ' + t;
    }
  }
  return '';
}`

// DetectCaptcha 返回识别到的验证码原因，没有则返回空串。
func DetectCaptcha(page *rod.Page) string {
	res, err := page.Eval(jsDetectCaptcha)
	if err != nil || res == nil {
		return ""
	}
	return res.Value.Str()
}

// SaveCaptchaSnapshot 把验证码现场（截图 + 元数据）落盘，供 MCP 调用方随后取走。
func SaveCaptchaSnapshot(page *rod.Page, title, reason string) error {
	if err := os.MkdirAll(captchaDir(), 0o755); err != nil {
		return err
	}

	shot, err := page.Screenshot(true, nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(captchaImagePath(), shot, 0o644); err != nil {
		return err
	}

	meta := CaptchaSnapshot{
		Title:      title,
		DetectedAt: time.Now().Format(time.RFC3339),
		Reason:     reason,
		ImagePath:  captchaImagePath(),
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(captchaMetaPath(), data, 0o644)
}

// LoadCaptchaSnapshot 读取最近一次验证码现场；没有快照时返回 (nil, nil)。
func LoadCaptchaSnapshot() (*CaptchaSnapshot, error) {
	data, err := os.ReadFile(captchaMetaPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var meta CaptchaSnapshot
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	image, err := os.ReadFile(captchaImagePath())
	if err != nil {
		return nil, err
	}
	meta.ImageBase64 = base64.StdEncoding.EncodeToString(image)
	return &meta, nil
}

// ClearCaptchaSnapshot 清掉旧快照，避免调用方取到上一次发布的验证码。
func ClearCaptchaSnapshot() {
	_ = os.Remove(captchaMetaPath())
	_ = os.Remove(captchaImagePath())
}
