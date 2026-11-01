package main

import (
	"html/template"
	"net/http"
)

var formTemplate = template.Must(template.New("form").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>FRP 访问授权</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; min-height: 100svh; padding: 20px; display: grid; place-items: center; background: #f3f5f8; color: #182235; font-family: system-ui, sans-serif; }
    main { width: 100%; max-width: 480px; padding: 28px; background: #fff; border: 1px solid #e0e5ed; border-radius: 16px; box-shadow: 0 8px 32px #1822350a; }
    h1 { margin: 0 0 12px; font-size: 26px; }
    p { line-height: 1.6; }
    .description { margin: 0 0 24px; color: #526077; }
    label { display: block; margin-bottom: 8px; font-weight: 600; }
    input { width: 100%; min-height: 56px; padding: 12px 16px; border: 1px solid #9aa8bc; border-radius: 8px; color: inherit; background: #fff; font: inherit; font-size: 24px; }
    input::placeholder { font-size: 18px; color: #68758b; }
    .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 16px; }
    button { flex: 1 1 180px; min-height: 48px; padding: 12px 16px; border: 1px solid #1d4ed8; border-radius: 8px; background: #1d4ed8; color: #fff; font: inherit; font-size: 18px; font-weight: 600; cursor: pointer; }
    button.secondary { background: #fff; color: #1d4ed8; }
    button:disabled { opacity: .6; cursor: wait; }
    input:focus-visible, button:focus-visible { outline: 3px solid #93b4ff; outline-offset: 3px; }
    .status { margin: 0 0 20px; padding: 12px 14px; border: 1px solid #a8d5b7; border-radius: 8px; background: #eef9f1; color: #205e35; overflow-wrap: anywhere; }
    .status[data-kind="error"] { border-color: #efb3b3; background: #fff1f1; color: #922626; }
    @media (max-width: 360px) { main { padding: 20px; } }
  </style>
</head>
<body>
<main>
  <h1>FRP 访问授权</h1>
  <p class="description">输入动态验证码，允许当前 IP 在 {{.Duration}} 内建立连接。</p>
  <p id="status" class="status" role="status" aria-live="polite" aria-atomic="true" data-kind="{{.Kind}}"{{if not .Message}} hidden{{end}}>{{.Message}}</p>
  <form method="post" action="/knock">
    <label for="code">动态验证码</label>
    <input id="code" name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="6 位动态验证码" required>
    <div class="actions">
      <button id="read-clipboard" class="secondary" type="button">读取剪贴板</button>
      <button type="submit">授权当前 IP</button>
    </div>
  </form>
</main>
<script>
  const code = document.getElementById('code');
  const status = document.getElementById('status');
  const clipboardButton = document.getElementById('read-clipboard');

  function showStatus(message, kind) {
    status.textContent = message;
    status.dataset.kind = kind;
    status.hidden = false;
  }

  clipboardButton.addEventListener('click', async () => {
    if (!navigator.clipboard || typeof navigator.clipboard.readText !== 'function') {
      showStatus('当前环境不支持读取剪贴板，请使用 HTTPS 访问，或手动粘贴验证码。', 'error');
      return;
    }
    clipboardButton.disabled = true;
    try {
      const text = (await navigator.clipboard.readText()).trim();
      if (!/^[0-9]{6}$/.test(text)) {
        showStatus('剪贴板内容须为 6 位数字，请复制正确的动态验证码。', 'error');
        return;
      }
      code.value = text;
      code.focus();
      showStatus('已填入验证码，请点击“授权当前 IP”提交。', 'success');
    } catch {
      showStatus('无法读取剪贴板，请允许剪贴板访问，或手动粘贴验证码。', 'error');
    } finally {
      clipboardButton.disabled = false;
    }
  });
</script>
</body>
</html>`))

func (s *Server) renderForm(w http.ResponseWriter, status int, message string) {
	kind := "success"
	if status >= http.StatusBadRequest {
		kind = "error"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = formTemplate.Execute(w, struct {
		Duration string
		Message  string
		Kind     string
	}{s.cfg.grantDuration.String(), message, kind})
}
