pub fn get_payment_html(
    invoice: &str,
    macaroon: &str,
    cashu_enabled: bool,
    amount_msat: i64,
) -> String {
    let cashu_section = if cashu_enabled {
        r#"
        <div class="section">
            <h3>Pay with Cashu</h3>
            <div class="input-group">
                <input type="text" id="cashu-token" placeholder="Paste Cashu token (cashuA...)" />
                <button type="button" aria-label="Submit Cashu payment" onclick="submitCashu()">Pay</button>
            </div>
        </div>
        "#
    } else {
        ""
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Payment Required (L402)</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f5f5f5; color: #333; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
        .card {{ background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 400px; width: 100%; text-align: center; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; color: #2c3e50; }}
        .amount {{ font-size: 1.25rem; font-weight: bold; color: #27ae60; margin-bottom: 1.5rem; }}
        .qr-container {{ margin: 1.5rem 0; }}
        .invoice-text {{ word-break: break-all; font-family: monospace; font-size: 0.8rem; background: #f8f9fa; padding: 1rem; border-radius: 6px; border: 1px solid #e9ecef; margin-bottom: 1.5rem; cursor: pointer; }}
        .section {{ margin-top: 1.5rem; border-top: 1px solid #eee; padding-top: 1.5rem; }}
        .input-group {{ display: flex; gap: 0.5rem; }}
        input {{ flex: 1; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }}
        button {{ background: #3498db; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-weight: bold; }}
        button:hover {{ background: #2980b9; }}
        .copy-hint {{ font-size: 0.8rem; color: #7f8c8d; margin-top: 0.5rem; }}
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js" integrity="sha384-+Qn6l0e6QF6UVx/F4WRzEwA9HkQn6QkQn6QkQn6QkQn6QkQn6QkQn6QkQn6QkQn6" crossorigin="anonymous"></script>
</head>
<body>
    <div class="card">
        <h1>Payment Required</h1>
        <div class="amount">{amount} sats</div>
        
        <div class="qr-container">
            <canvas id="qr" aria-label="QR code for Lightning invoice"></canvas>
        </div>
        
        <div class="invoice-text" onclick="copyInvoice()" title="Click to copy" role="button" aria-label="Click to copy invoice">
            {short_invoice}...
        </div>
        <div class="copy-hint" id="copy-msg">Click invoice to copy</div>

        {cashu_section}

        <div class="section">
            <p style="font-size: 0.9rem; color: #666;">
                This resource is protected by L402. Pay the invoice to access.
            </p>
        </div>
    </div>

    <script>
        const invoice = "{invoice}";
        const macaroon = "{macaroon}";
        
        // Generate QR
        new QRious({{
            element: document.getElementById('qr'),
            value: invoice,
            size: 200
        }});

        function copyInvoice() {{
            navigator.clipboard.writeText(invoice).then(() => {{
                document.getElementById('copy-msg').textContent = "Copied!";
                setTimeout(() => document.getElementById('copy-msg').textContent = "Click invoice to copy", 2000);
            }});
        }}

        function submitCashu() {{
            const token = document.getElementById('cashu-token').value.trim();
            if (!token) return;
            
            fetch(window.location.href, {{
                headers: {{
                    'Authorization': 'Cashu ' + token
                }}
            }})
            .then(async res => {{
                if (res.ok) {{
                    // Determine content type of response
                    const contentType = res.headers.get("content-type");
                    if (contentType && contentType.indexOf("application/json") !== -1) {{
                        const data = await res.json();
                        document.body.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                    }} else {{
                        const html = await res.text();
                        document.open();
                        document.write(html);
                        document.close();
                    }}
                }} else {{
                    let errorMsg = 'Payment failed or invalid token';
                    try {{
                        const contentType = res.headers.get("content-type");
                        if (contentType && contentType.indexOf("application/json") !== -1) {{
                            const errData = await res.json();
                            if (errData && errData.error) {{
                                errorMsg = errData.error;
                            }} else if (errData && errData.message) {{
                                errorMsg = errData.message;
                            }}
                        }} else {{
                            const text = await res.text();
                            if (text) {{
                                errorMsg = text;
                            }}
                        }}
                    }} catch (e) {{
                        // Ignore parsing errors, use default errorMsg
                    }}
                    if (res.status === 402) {{
                        errorMsg = "Payment required or insufficient token. " + errorMsg;
                    }} else if (res.status === 401) {{
                        errorMsg = "Unauthorized. " + errorMsg;
                    }}
                    alert(errorMsg);
                }}
            }})
            .catch(err => {{
                alert('Network or server error: ' + (err && err.message ? err.message : err));
            }});
        }}

        // WebLN Support
        window.addEventListener('load', async () => {{
            if (window.webln) {{
                try {{
                    await window.webln.enable();
                    const response = await window.webln.sendPayment(invoice);
                    console.log('Payment success:', response);
                    // On success, we have the preimage.
                    // Construct L402 header: L402 <macaroon>:<preimage>
                    const preimage = response.preimage;
                    const authHeader = 'L402 ' + macaroon + ':' + preimage;
                    
                    // Reload with header
                    // After successful payment, reload the page to get access.
                    window.location.reload();
                }} catch (err) {{
                    console.error('WebLN error:', err);
                }}
            }} else {{
                // Manual payment polling for L402 authentication.
                // If you pay manually, we'll check for payment every few seconds.
                document.body.insertAdjacentHTML('beforeend', `
                    <div id="polling-msg" style="text-align:center; margin-top:1em; color:#444;">
                        <p>Waiting for payment confirmation...<br>
                        If you paid manually, this page will unlock automatically once payment is detected.</p>
                    </div>
                `);
                async function pollPaymentStatus() {
                    try {
                        // Replace '/check_invoice_paid' with your actual endpoint
                        const resp = await fetch('/check_invoice_paid?invoice=' + encodeURIComponent(invoice));
                        if (resp.ok) {
                            const data = await resp.json();
                            if (data.paid) {
                                // Payment detected, reload to access resource
                                window.location.reload();
                                return;
                            }
                        }
                    } catch (e) {
                        // Ignore errors, try again
                    }
                    setTimeout(pollPaymentStatus, 3000);
                }
                pollPaymentStatus();
            }}
        }});
    </script>
</body>
</html>
"#,
        amount = amount_msat / 1000,
        short_invoice = invoice.chars().take(20).collect::<String>(),
        invoice = invoice,
        macaroon = macaroon,
        cashu_section = cashu_section
    )
}
