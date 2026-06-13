//! Payment page HTML renderer for the L402 402-challenge response.
//!
//! Separated from `lib.rs` to keep the core module focused on Nginx plumbing.
//! This module owns all HTML, CSS, and JavaScript that is sent to the browser
//! when a protected resource requires payment.

/// Escape a string for safe interpolation into HTML text/attribute contexts.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Render the full 402 payment page as an HTML string.
///
/// # Arguments
/// * `invoice`               - BOLT-11 invoice string (used for QR + copy)
/// * `amount_msat`           - Amount in millisatoshis (displayed as sats)
/// * `macaroon_b64`          - Base64-encoded macaroon token
/// * `auto_detect`           - Whether to poll for automatic payment detection
/// * `cashu_enabled`         - Whether to show the Cashu/eCash tab
/// * `cashu_payment_request` - Optional P2PK Cashu payment request string
pub fn render_payment_page(
    invoice: &str,
    amount_msat: i64,
    macaroon_b64: &str,
    auto_detect: bool,
    cashu_enabled: bool,
    cashu_payment_request: Option<&str>,
) -> String {
    // ── QR Code ─────────────────────────────────────────────────────────────
    // Generate at 280 px and inject centering styles into the SVG root so the
    // image always fills its white card wrapper without cropping.
    let raw_qr = qrcode_generator::to_svg_to_string(
        invoice.to_uppercase(),
        qrcode_generator::QrCodeEcc::Medium,
        280,
        None::<&str>,
    )
    .unwrap_or_else(|_| {
        "<svg xmlns='http://www.w3.org/2000/svg' width='280' height='280'>\
         <rect width='280' height='280' fill='#1a1a2e'/>\
         <text x='140' y='140' text-anchor='middle' fill='#8b5cf6' font-size='12'>QR Error</text>\
         </svg>"
            .to_string()
    });

    let qr_svg = raw_qr.replacen(
        "<svg ",
        "<svg viewBox=\"0 0 280 280\" style=\"display:block;width:100%;height:auto;max-width:280px;\" ",
        1,
    );

    // ── Amounts ──────────────────────────────────────────────────────────────
    let amount_sats = amount_msat / 1000;
    let invoice_short = if invoice.chars().count() > 40 {
        let head: String = invoice.chars().take(20).collect();
        let tail: String = invoice.chars().rev().take(10).collect::<String>()
            .chars().rev().collect();
        html_escape(&format!("{}\u{2026}{}", head, tail))
    } else {
        html_escape(invoice)
    };

    // ── Cashu tab ────────────────────────────────────────────────────────────
    let cashu_tab_html = if cashu_enabled {
        let payment_req_hint = cashu_payment_request
            .map(|r| {
                let preview = html_escape(&r.chars().take(60).collect::<String>());
                format!(
                    "<div class=\"payment-req-box\">\
<span class=\"payment-req-label\">Payment Request</span>\
<code class=\"payment-req-code\">{preview}\u{2026}</code>\
</div>",
                    preview = preview,
                )
            })
            .unwrap_or_default();
        format!(
            "<div id=\"tab-ecash\" class=\"tab-panel hidden\">\
<div class=\"card\">\
<div class=\"cashu-header\">\
<span class=\"cashu-icon\">🥜</span>\
<div>\
<div class=\"cashu-title\">Pay with Cashu eCash</div>\
<div class=\"cashu-subtitle\">Paste a Cashu token to instantly unlock access</div>\
</div>\
</div>\
{payment_req_hint}\
<div class=\"field\">\
<label for=\"cashu-token\">Cashu Token</label>\
<textarea id=\"cashu-token\" placeholder=\"cashuA...\" rows=\"4\" spellcheck=\"false\" autocomplete=\"off\"></textarea>\
</div>\
<button class=\"btn btn-cashu\" onclick=\"submitCashu()\">🥜 Submit Token</button>\
<div id=\"cashu-error\" class=\"error-msg hidden\"></div>\
</div>\
</div>",
            payment_req_hint = payment_req_hint,
        )
    } else {
        String::new()
    };

    let ecash_tab_btn = if cashu_enabled {
        "<button class=\"tab-btn\" id=\"tab-btn-ecash\" onclick=\"switchTab('ecash')\">🥜 ECASH</button>"
    } else {
        ""
    };

    // ── Auto-detect polling JS ────────────────────────────────────────────────
    let auto_detect_js = if auto_detect {
        format!(
            r#"
    let pollAttempts = 0;
    const MAX_POLL = 100;
    function startPolling() {{
        if (pollAttempts++ > MAX_POLL) {{
            document.getElementById('auto-status').classList.add('hidden');
            document.getElementById('preimage-section').classList.remove('hidden');
            return;
        }}
        fetch(window.location.href, {{
            headers: {{'Authorization': 'L402 ' + {mac}}},
            redirect: 'follow',
            credentials: 'same-origin'
        }}).then(r => {{
            if (r.ok || r.status === 200) {{
                document.getElementById('auto-status').innerHTML =
                    '<span style="color:var(--success)">✓ Payment confirmed! Redirecting…</span>';
                setTimeout(() => window.location.reload(), 800);
            }} else {{
                setTimeout(startPolling, 3000);
            }}
        }}).catch(() => setTimeout(startPolling, 3000));
    }}
    startPolling();
"#,
            mac = serde_json::to_string(macaroon_b64)
                .unwrap_or_else(|_| "\"\"".to_string())
        )
    } else {
        String::new()
    };

    let auto_detect_section = if auto_detect {
        "<div id=\"auto-status\" class=\"auto-status\">\
<div class=\"spinner\"></div>\
<span>Waiting for payment confirmation\u{2026}</span>\
<button class=\"btn-link\" onclick=\"document.getElementById('auto-status').classList.add('hidden');\
document.getElementById('preimage-section').classList.remove('hidden')\">Enter preimage manually</button>\
</div>"
    } else {
        ""
    };

    let preimage_hidden_class = if auto_detect { "hidden" } else { "" };

    // ── Full HTML page ────────────────────────────────────────────────────────
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>402 Payment Required &#8212; L402</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  :root{{
    --bg:#07070f;--surface:#0d0d1a;--surface2:#13132a;--border:#1e1e3a;
    --accent:#7c3aed;--accent2:#a855f7;--accent-glow:rgba(124,58,237,.35);
    --cashu:#f59e0b;--cashu-glow:rgba(245,158,11,.25);
    --text:#e2e2f0;--text-muted:#8080a8;--text-dim:#3a3a5c;
    --success:#10b981;--error:#ef4444;
  }}
  html,body{{height:100%;background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:15px;line-height:1.6}}
  body{{
    display:flex;align-items:flex-start;justify-content:center;min-height:100vh;
    padding:2rem 1.5rem;overflow-y:auto;
    background-image:
      radial-gradient(ellipse 90% 70% at 50% -10%, rgba(124,58,237,.22), transparent),
      radial-gradient(ellipse 60% 50% at 85% 90%, rgba(168,85,247,.1), transparent),
      radial-gradient(ellipse 40% 30% at 10% 80%, rgba(124,58,237,.06), transparent);
  }}
  .container{{width:100%;max-width:460px;display:flex;flex-direction:column;gap:1.2rem}}
  /* Header */
  .header{{text-align:center;padding-bottom:.25rem}}
  .badge{{display:inline-flex;align-items:center;gap:.4rem;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.28);border-radius:9999px;padding:.28rem .85rem;font-size:.72rem;font-weight:700;letter-spacing:.1em;color:#f87171;margin-bottom:.85rem;text-transform:uppercase}}
  .header h1{{font-size:1.65rem;font-weight:700;letter-spacing:-.025em;background:linear-gradient(135deg,#e2e2f0 0%,#c084fc 60%,#a855f7 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:.35rem}}
  .header p{{color:var(--text-muted);font-size:.88rem}}
  .amount{{display:inline-flex;align-items:baseline;gap:.35rem;margin-top:.6rem;background:linear-gradient(135deg,rgba(124,58,237,.12),rgba(168,85,247,.06));border:1px solid rgba(124,58,237,.28);border-radius:.8rem;padding:.45rem 1.1rem;box-shadow:0 0 20px rgba(124,58,237,.08)}}
  .amount-num{{font-size:1.55rem;font-weight:700;color:#c084fc}}
  .amount-unit{{font-size:.78rem;color:var(--text-muted);font-weight:500}}
  /* Tabs */
  .tabs{{display:flex;background:rgba(13,13,26,.9);border:1px solid var(--border);border-radius:.85rem;padding:.3rem;gap:.3rem;box-shadow:0 4px 24px rgba(0,0,0,.35)}}
  .tab-btn{{flex:1;padding:.52rem .5rem;border:none;border-radius:.55rem;background:transparent;color:var(--text-muted);font-size:.76rem;font-weight:600;letter-spacing:.05em;cursor:pointer;transition:all .22s;display:flex;align-items:center;justify-content:center;gap:.35rem}}
  .tab-btn.active{{background:var(--accent);color:#fff;box-shadow:0 0 18px var(--accent-glow)}}
  .tab-btn:hover:not(.active){{background:var(--surface2);color:var(--text)}}
  /* Cards */
  .card{{background:rgba(13,13,26,.85);border:1px solid var(--border);border-radius:1.1rem;padding:1.35rem;backdrop-filter:blur(16px);display:flex;flex-direction:column;gap:1.1rem;box-shadow:0 8px 40px rgba(0,0,0,.4)}}
  .tab-panel{{display:flex;flex-direction:column;gap:1rem}}
  .tab-panel.hidden{{display:none}}
  /* QR — white card with overflow:hidden so the SVG never bleeds */
  .qr-wrap{{display:flex;align-items:center;justify-content:center;background:linear-gradient(145deg,rgba(255,255,255,.97),rgba(248,248,255,.95));border-radius:.85rem;padding:1.1rem;overflow:hidden;box-shadow:0 2px 24px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.8)}}
  /* Invoice strip */
  .invoice-box{{background:var(--surface2);border:1px solid var(--border);border-radius:.65rem;padding:.7rem .9rem;display:flex;align-items:center;gap:.65rem;cursor:pointer;transition:border-color .2s,background .2s}}
  .invoice-box:hover{{border-color:var(--accent2);background:rgba(124,58,237,.06)}}
  .invoice-text{{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--text-muted);flex:1;word-break:break-all;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}}
  .copy-icon{{flex-shrink:0;color:var(--text-dim);font-size:1rem;transition:color .2s}}
  .invoice-box:hover .copy-icon{{color:var(--accent2)}}
  .copy-toast{{font-size:.72rem;color:var(--success);text-align:center;opacity:0;transition:opacity .3s;height:1rem}}
  /* Auto-detect */
  .auto-status{{display:flex;flex-direction:column;align-items:center;gap:.65rem;padding:.85rem;background:rgba(124,58,237,.07);border:1px solid rgba(124,58,237,.2);border-radius:.85rem;text-align:center}}
  .auto-status span{{font-size:.85rem;color:var(--text-muted)}}
  .spinner{{width:22px;height:22px;border:2.5px solid rgba(124,58,237,.18);border-top-color:var(--accent2);border-radius:50%;animation:spin .85s linear infinite}}
  @keyframes spin{{to{{transform:rotate(360deg)}}}}
  .btn-link{{background:none;border:none;color:var(--text-dim);font-size:.73rem;cursor:pointer;text-decoration:underline;padding:0;margin-top:.2rem;transition:color .2s}}
  .btn-link:hover{{color:var(--accent2)}}
  /* Forms */
  label{{font-size:.72rem;font-weight:700;color:var(--text-muted);letter-spacing:.06em;text-transform:uppercase}}
  input,textarea{{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:.65rem;padding:.7rem .9rem;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:.8rem;outline:none;resize:vertical;transition:border-color .2s,box-shadow .2s}}
  input:focus,textarea:focus{{border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,58,237,.14)}}
  input::placeholder,textarea::placeholder{{color:var(--text-dim)}}
  .field{{display:flex;flex-direction:column;gap:.45rem}}
  /* Buttons */
  .btn{{display:flex;align-items:center;justify-content:center;gap:.5rem;width:100%;padding:.75rem 1.25rem;border:none;border-radius:.75rem;font-weight:600;font-size:.88rem;cursor:pointer;transition:all .25s;letter-spacing:.01em}}
  .btn-primary{{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 4px 22px var(--accent-glow)}}
  .btn-primary:hover{{transform:translateY(-2px);box-shadow:0 8px 32px var(--accent-glow)}}
  .btn-primary:active{{transform:translateY(0)}}
  .btn-cashu{{background:linear-gradient(135deg,#d97706,var(--cashu));color:#fff;box-shadow:0 4px 22px var(--cashu-glow)}}
  .btn-cashu:hover{{transform:translateY(-2px);box-shadow:0 8px 32px var(--cashu-glow)}}
  .btn-cashu:active{{transform:translateY(0)}}
  /* Cashu section */
  .cashu-header{{display:flex;align-items:center;gap:.85rem}}
  .cashu-icon{{font-size:2rem;line-height:1}}
  .cashu-title{{font-weight:600;font-size:.95rem;color:var(--text);margin-bottom:.15rem}}
  .cashu-subtitle{{font-size:.78rem;color:var(--text-muted)}}
  .payment-req-box{{background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.2);border-radius:.65rem;padding:.65rem .85rem;display:flex;flex-direction:column;gap:.3rem}}
  .payment-req-label{{font-size:.68rem;font-weight:700;letter-spacing:.08em;color:#d97706;text-transform:uppercase}}
  .payment-req-code{{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--text-muted);word-break:break-all;line-height:1.5}}
  /* Misc */
  .error-msg{{background:rgba(239,68,68,.09);border:1px solid rgba(239,68,68,.22);border-radius:.55rem;padding:.55rem .8rem;font-size:.8rem;color:#f87171}}
  .error-msg.hidden{{display:none}}
  .divider{{border:none;border-top:1px solid var(--border);margin:.2rem 0}}
  .footer{{text-align:center;font-size:.7rem;color:var(--text-dim);padding-top:.25rem}}
  .footer a{{color:var(--text-dim);text-decoration:none;transition:color .2s}}
  .footer a:hover{{color:var(--accent2)}}
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <div class="badge">&#9889; 402 Payment Required</div>
    <h1>Lightning Payment</h1>
    <p>Access to this resource requires a payment</p>
    <div class="amount">
      <span class="amount-num">{amount_sats}</span>
      <span class="amount-unit">sats ({amount_msat} msats)</span>
    </div>
  </div>
  <!-- Tabs -->
  <div class="tabs">
    <button class="tab-btn active" id="tab-btn-lightning" onclick="switchTab('lightning')">&#9889; LIGHTNING</button>
    <!-- tab-btn-ecash injected below if cashu is enabled -->
    {ecash_tab_btn}
  </div>
  <!-- Lightning Tab -->
  <div id="tab-lightning" class="tab-panel">
    <div class="card">
      <div class="qr-wrap">{qr_svg}</div>
      <div class="invoice-box" onclick="copyInvoice()" title="Click to copy full invoice">
        <span class="invoice-text">{invoice_short}</span>
        <span class="copy-icon">&#10697;</span>
      </div>
      <div class="copy-toast" id="copy-toast">Copied to clipboard!</div>
      <hr class="divider">
      {auto_detect_section}
      <div id="preimage-section" class="{preimage_hidden_class}">
        <div class="field">
          <label for="preimage-input">After paying, enter the preimage</label>
          <input id="preimage-input" type="text" placeholder="Enter preimage (hex)" autocomplete="off" spellcheck="false">
        </div>
        <button class="btn btn-primary" onclick="submitPreimage()">Submit Payment</button>
        <div id="preimage-error" class="error-msg hidden"></div>
      </div>
    </div>
  </div>
  {cashu_tab_html}
  <div class="footer">
    Secured by <a href="https://github.com/DhananjayPurohit/ngx_l402" target="_blank" rel="noopener">ngx_l402</a> &#183; L402 Protocol
  </div>
</div>
<script>
  const INVOICE = {invoice_json};
  const MACAROON = {macaroon_json};
  function switchTab(name) {{
    ['lightning','ecash'].forEach(t => {{
      const panel = document.getElementById('tab-' + t);
      const btn   = document.getElementById('tab-btn-' + t);
      if (!panel || !btn) return;
      if (t === name) {{ panel.classList.remove('hidden'); btn.classList.add('active'); }}
      else {{ panel.classList.add('hidden'); btn.classList.remove('active'); }}
    }});
  }}
  function copyInvoice() {{
    navigator.clipboard.writeText(INVOICE).then(() => {{
      const t = document.getElementById('copy-toast');
      t.style.opacity = '1'; setTimeout(() => t.style.opacity = '0', 2000);
    }}).catch(() => {{
      const box = document.createElement('textarea');
      box.value = INVOICE; document.body.appendChild(box); box.select();
      document.execCommand('copy'); document.body.removeChild(box);
      const t = document.getElementById('copy-toast');
      t.style.opacity = '1'; setTimeout(() => t.style.opacity = '0', 2000);
    }});
  }}
  function submitPreimage() {{
    const hex = document.getElementById('preimage-input').value.trim();
    const errEl = document.getElementById('preimage-error');
    if (!/^[0-9a-fA-F]{{64}}$/.test(hex)) {{
      errEl.textContent = 'Invalid preimage \u2014 must be 64 hex characters.';
      errEl.classList.remove('hidden'); return;
    }}
    errEl.classList.add('hidden');
    const btn = event.currentTarget; btn.textContent = 'Verifying\u2026'; btn.disabled = true;
    fetch(window.location.href, {{
      method: 'GET',
      headers: {{'Authorization': 'L402 ' + MACAROON + ':' + hex}},
      redirect: 'follow', credentials: 'same-origin'
    }}).then(r => {{
      if (r.ok || r.status === 200) {{ window.location.reload(); }}
      else {{
        errEl.textContent = 'Payment verification failed (status ' + r.status + '). Check your preimage.';
        errEl.classList.remove('hidden'); btn.textContent = 'Submit Payment'; btn.disabled = false;
      }}
    }}).catch(e => {{
      errEl.textContent = 'Network error: ' + e.message;
      errEl.classList.remove('hidden'); btn.textContent = 'Submit Payment'; btn.disabled = false;
    }});
  }}
  function submitCashu() {{
    const token = document.getElementById('cashu-token').value.trim();
    const errEl = document.getElementById('cashu-error');
    if (!token.startsWith('cashu')) {{
      errEl.textContent = 'Invalid Cashu token \u2014 must start with "cashu".';
      errEl.classList.remove('hidden'); return;
    }}
    errEl.classList.add('hidden');
    const btn = event.currentTarget; btn.textContent = 'Verifying\u2026'; btn.disabled = true;
    fetch(window.location.href, {{
      method: 'GET',
      headers: {{'Authorization': 'Cashu ' + token}},
      redirect: 'follow', credentials: 'same-origin'
    }}).then(r => {{
      if (r.ok || r.status === 200) {{ window.location.reload(); }}
      else {{
        errEl.textContent = 'Token verification failed (status ' + r.status + ').';
        errEl.classList.remove('hidden'); btn.textContent = 'Submit Token'; btn.disabled = false;
      }}
    }}).catch(e => {{
      errEl.textContent = 'Network error: ' + e.message;
      errEl.classList.remove('hidden'); btn.textContent = 'Submit Token'; btn.disabled = false;
    }});
  }}
  {auto_detect_js}
</script>
</body>
</html>"#,
        amount_sats = amount_sats,
        amount_msat = amount_msat,
        ecash_tab_btn = ecash_tab_btn,
        qr_svg = qr_svg,
        invoice_short = invoice_short,
        auto_detect_section = auto_detect_section,
        preimage_hidden_class = preimage_hidden_class,
        cashu_tab_html = cashu_tab_html,
        invoice_json = serde_json::to_string(invoice).unwrap_or_else(|_| "\"\"".to_string()).replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026"),
        macaroon_json = serde_json::to_string(macaroon_b64).unwrap_or_else(|_| "\"\"".to_string()).replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026"),
        auto_detect_js = auto_detect_js,
    )
}
