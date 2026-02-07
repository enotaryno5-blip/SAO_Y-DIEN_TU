using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

using iText.Kernel.Pdf;
using iText.Signatures;
using iText.IO.Image;
using iText.Forms.Form.Element;

using iText.Bouncycastleconnector;
using iText.Commons.Bouncycastle;
using iText.Commons.Bouncycastle.Cert;

namespace LocalPdfSigner;

public class Program
{
    // File cấu hình sẽ nằm cùng thư mục với file .exe (AppContext.BaseDirectory)
    private static string ConfigPath => System.IO.Path.Combine(AppContext.BaseDirectory, "config.json");

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        // ====== CORS để file:// index.html gọi được http://127.0.0.1:8989 ======
        app.Use(async (ctx, next) =>
        {
            ctx.Response.Headers["Access-Control-Allow-Origin"] = "*";
            ctx.Response.Headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS";
            ctx.Response.Headers["Access-Control-Allow-Headers"] = "Content-Type";

            if (ctx.Request.Method == "OPTIONS")
            {
                ctx.Response.StatusCode = 200;
                await ctx.Response.CompleteAsync();
                return;
            }

            await next();
        });

        // Health
        app.MapGet("/health", () => Results.Text("ok", "text/plain"));

        // ====== UI (người dùng chỉ cần chọn, không copy/paste) ======
        app.MapGet("/ui", () =>
        {
            // Trang cấu hình rất đơn giản: load /certs, load /config, cho chọn & lưu
            var html = """
<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Cấu hình Token ký số</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; margin:16px; line-height:1.35}
    .box{max-width:920px; margin:0 auto; padding:16px; border:1px solid #ddd; border-radius:12px}
    h1{font-size:20px; margin:0 0 12px}
    .row{display:flex; gap:12px; flex-wrap:wrap; margin:10px 0}
    label{display:block; font-weight:600; margin-bottom:6px}
    select{width:100%; padding:10px; border-radius:10px; border:1px solid #bbb}
    button{padding:10px 14px; border-radius:10px; border:1px solid #333; background:#111; color:#fff; cursor:pointer}
    button:disabled{opacity:.6; cursor:not-allowed}
    .hint{color:#555; font-size:13px}
    .ok{color:#0a7a2f; font-weight:700}
    .err{color:#b00020; font-weight:700}
    .small{font-size:12px; color:#666; word-break:break-all}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  </style>
</head>
<body>
  <div class="box">
    <h1>Chọn chứng thư để ký (CCV / Tổ chức)</h1>
    <div class="hint">Cắm token vào máy → bấm “Tải danh sách” → chọn đúng chứng thư cho CCV và TC → bấm “Lưu cấu hình”.</div>

    <div class="row" style="margin-top:12px">
      <button id="reloadBtn">Tải danh sách</button>
      <button id="saveBtn" disabled>Lưu cấu hình</button>
      <div id="msg" style="margin-left:auto; font-weight:700"></div>
    </div>

    <div class="row">
      <div style="flex:1; min-width:320px">
        <label>Chứng thư ký CCV</label>
        <select id="ccvSel"></select>
        <div class="small mono" id="ccvTp"></div>
      </div>
      <div style="flex:1; min-width:320px">
        <label>Chứng thư ký Tổ chức (TC)</label>
        <select id="tcSel"></select>
        <div class="small mono" id="tcTp"></div>
      </div>
    </div>

    <div class="row">
      <div style="flex:1; min-width:320px">
        <div class="hint">Config hiện tại:</div>
        <div class="small mono" id="cfgBox">(chưa có)</div>
      </div>
      <div style="flex:1; min-width:320px">
        <div class="hint">Mẹo:</div>
        <div class="hint">Nếu đổi token, chỉ cần mở lại trang này và chọn lại cho đúng. Không cần dán lệnh/copy thumbprint.</div>
      </div>
    </div>
  </div>

<script>
const $ = (id)=>document.getElementById(id);

function setMsg(text, cls){
  const el = $("msg");
  el.textContent = text || "";
  el.className = cls || "";
}

function fmtOpt(c){
  const s = (c.subject||"").replace("CN=","");
  const i = (c.issuer||"").replace("CN=","");
  const exp = c.notAfter ? new Date(c.notAfter).toLocaleString("vi-VN") : "";
  return `${s}  |  Issuer: ${i}  |  Hết hạn: ${exp}`;
}

async function loadConfig(){
  try{
    const r = await fetch("/config");
    if(!r.ok){ $("cfgBox").textContent="(chưa có)"; return null; }
    const t = await r.text();
    $("cfgBox").textContent = t;
    return JSON.parse(t);
  }catch(e){
    $("cfgBox").textContent="(lỗi đọc config)";
    return null;
  }
}

async function loadCerts(){
  setMsg("Đang tải...", "");
  $("saveBtn").disabled = true;

  const r = await fetch("/certs");
  if(!r.ok){ setMsg("Lỗi /certs", "err"); return; }
  const certs = await r.json();

  // fill selects
  const ccvSel = $("ccvSel");
  const tcSel  = $("tcSel");
  ccvSel.innerHTML = "";
  tcSel.innerHTML = "";

  certs.forEach(c=>{
    const o1 = document.createElement("option");
    o1.value = c.thumbprint;
    o1.textContent = fmtOpt(c);
    ccvSel.appendChild(o1);

    const o2 = document.createElement("option");
    o2.value = c.thumbprint;
    o2.textContent = fmtOpt(c);
    tcSel.appendChild(o2);
  });

  // load saved config and preselect if exists
  const cfg = await loadConfig();
  if(cfg){
    if(cfg.ccvThumbprint) ccvSel.value = cfg.ccvThumbprint;
    if(cfg.tcThumbprint)  tcSel.value  = cfg.tcThumbprint;
  }

  $("ccvTp").textContent = ccvSel.value ? ("Thumbprint: " + ccvSel.value) : "";
  $("tcTp").textContent  = tcSel.value ? ("Thumbprint: " + tcSel.value) : "";

  $("saveBtn").disabled = (certs.length === 0);
  setMsg(certs.length ? `Đã tải ${certs.length} chứng thư` : "Không có chứng thư nào có Private Key", certs.length ? "ok" : "err");
}

function bindSel(){
  $("ccvSel").addEventListener("change", ()=> $("ccvTp").textContent = $("ccvSel").value ? ("Thumbprint: " + $("ccvSel").value) : "");
  $("tcSel").addEventListener("change",  ()=> $("tcTp").textContent  = $("tcSel").value ? ("Thumbprint: " + $("tcSel").value) : "");
}

async function saveCfg(){
  const ccv = $("ccvSel").value || "";
  const tc  = $("tcSel").value  || "";
  if(!ccv || !tc){ setMsg("Chưa chọn đủ CCV/TC", "err"); return; }

  setMsg("Đang lưu...", "");
  const r = await fetch("/config", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ ccvThumbprint: ccv, tcThumbprint: tc })
  });
  const t = await r.text();
  if(!r.ok){ setMsg("Lưu lỗi: " + t, "err"); return; }

  setMsg("Đã lưu cấu hình", "ok");
  await loadConfig();
}

$("reloadBtn").addEventListener("click", loadCerts);
$("saveBtn").addEventListener("click", saveCfg);
bindSel();
loadCerts();
</script>
</body>
</html>
""";
            return Results.Text(html, "text/html; charset=utf-8");
        });

        // ====== LIST CERTS: GET /certs ======
        app.MapGet("/certs", () =>
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            var now = DateTime.Now;

            var certs = store.Certificates
                .Cast<X509Certificate2>()
                .Where(c =>
                {
                    if (!c.HasPrivateKey) return false;
                    if (c.NotBefore > now) return false;
                    if (c.NotAfter < now) return false;
                    return true;
                })
                .Select(c => new
                {
                    subject = c.Subject,
                    issuer = c.Issuer,
                    thumbprint = NormalizeThumbprint(c.Thumbprint),
                    notBefore = c.NotBefore,
                    notAfter = c.NotAfter,
                    serialNumber = c.SerialNumber,
                    friendlyName = c.FriendlyName
                })
                .OrderBy(x => x.notAfter)
                .ToList();

            return Results.Ok(certs);
        });

        // ====== SAVE CONFIG: POST /config ======
        app.MapPost("/config", async (SaveConfigRequest req) =>
        {
            var ccv = NormalizeThumbprint(req.ccvThumbprint);
            var tc = NormalizeThumbprint(req.tcThumbprint);

            if (string.IsNullOrWhiteSpace(ccv) || string.IsNullOrWhiteSpace(tc))
                return Results.BadRequest("Thiếu thumbprint CCV/TC");

            var config = new SignConfig
            {
                ccvThumbprint = ccv,
                tcThumbprint = tc
            };

            var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(ConfigPath, json);

            return Results.Ok(new { saved = true, path = ConfigPath });
        });

        // ====== READ CONFIG: GET /config ======
        app.MapGet("/config", () =>
        {
            if (!File.Exists(ConfigPath)) return Results.NotFound("Chưa có config.json");
            return Results.Text(File.ReadAllText(ConfigPath), "application/json");
        });

        // ====== SIGN: POST /sign ======
        app.MapPost("/sign", (SignRequest req) =>
        {
            if (string.IsNullOrWhiteSpace(req.PdfBase64))
                return Results.BadRequest("Thiếu pdfBase64.");

            byte[] inputPdf;
            try
            {
                inputPdf = Convert.FromBase64String(req.PdfBase64);
            }
            catch
            {
                return Results.BadRequest("pdfBase64 không hợp lệ.");
            }

            // Role (CCV / TC)
            var role = (req.Role ?? "CCV").Trim().ToUpperInvariant();
            if (role != "CCV" && role != "TC") role = "CCV";

            // Load config (không hard-code)
            var config = LoadConfigOrNull();
            if (config == null)
                return Results.BadRequest("Chưa cấu hình chứng thư. Mở http://127.0.0.1:8989/ui để chọn CCV/TC.");

            var thumbprint = role == "TC" ? config.tcThumbprint : config.ccvThumbprint;
            if (string.IsNullOrWhiteSpace(thumbprint))
                return Results.BadRequest("Config thiếu thumbprint cho role đang ký.");

            // Load certificate
            X509Certificate2 cert;
            try
            {
                cert = LoadCertificateByThumbprintCurrentUserMy(thumbprint);
            }
            catch (Exception ex)
            {
                return Results.BadRequest("Không tìm thấy chứng thư theo cấu hình. Nếu Ông/bà vừa đổi token, mở /ui để chọn lại. Chi tiết: " + ex.Message);
            }

            // Build chain iText
            var chain = BuildITextCertificateChain(cert);

            // Ký
            using var reader = new PdfReader(new MemoryStream(inputPdf));
            using var output = new MemoryStream();

            var signer = new PdfSigner(reader, output, new StampingProperties().UseAppendMode());

            // Vị trí hiển thị chữ ký
            var pageNumber = req.PageNumber ?? 1;
            if (pageNumber < 1) pageNumber = 1;

            float x = req.X ?? 50f;
            float y = req.Y ?? 50f;
            float w = req.W ?? 200f;
            float h = req.H ?? 80f;
            if (w <= 0) w = 200f;
            if (h <= 0) h = 80f;

            var signerProps = new SignerProperties()
                .SetFieldName(string.IsNullOrWhiteSpace(req.FieldName) ? "Sig1" : req.FieldName!.Trim())
                .SetPageNumber(pageNumber)
                .SetPageRect(new iText.Kernel.Geom.Rectangle(x, y, w, h));

            if (!string.IsNullOrWhiteSpace(req.Reason))
                signerProps.SetReason(req.Reason!.Trim());

            if (!string.IsNullOrWhiteSpace(req.Location))
                signerProps.SetLocation(req.Location!.Trim());

            // Ảnh hiển thị (áp dụng cho CCV & TC)
            if (!string.IsNullOrWhiteSpace(req.AppearancePngBase64))
            {
                try
                {
                    var dataUrl = req.AppearancePngBase64.Trim();
                    var b64 = dataUrl.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
                        ? dataUrl.Substring(dataUrl.IndexOf("base64,", StringComparison.OrdinalIgnoreCase) + 7)
                        : dataUrl;

                    var imgBytes = Convert.FromBase64String(b64);

                    var appearance = new SignatureFieldAppearance(SignerProperties.IGNORED_ID)
                        .SetContent(ImageDataFactory.Create(imgBytes));

                    signerProps.SetSignatureAppearance(appearance);
                }
                catch
                {
                    // ảnh lỗi thì vẫn ký bình thường
                }
            }

            signer.SetSignerProperties(signerProps);

            IExternalSignature extSig = new TokenExternalSignature(cert);

            signer.SignDetached(
                extSig,
                chain,
                null, null, null,
                0,
                PdfSigner.CryptoStandard.CMS
            );

            return Results.File(output.ToArray(), "application/pdf", "signed.pdf");
        });

        // Chạy đúng port 8989
        app.Run("http://127.0.0.1:8989");
    }

    // ====== helpers ======
    private static SignConfig? LoadConfigOrNull()
    {
        try
        {
            if (!File.Exists(ConfigPath)) return null;
            var json = File.ReadAllText(ConfigPath);
            var cfg = JsonSerializer.Deserialize<SignConfig>(json);
            if (cfg == null) return null;
            cfg.ccvThumbprint = NormalizeThumbprint(cfg.ccvThumbprint);
            cfg.tcThumbprint = NormalizeThumbprint(cfg.tcThumbprint);
            return cfg;
        }
        catch
        {
            return null;
        }
    }

    private static X509Certificate2 LoadCertificateByThumbprintCurrentUserMy(string thumbprint)
    {
        thumbprint = NormalizeThumbprint(thumbprint);

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        if (found.Count == 0)
            throw new Exception("Không tìm thấy chứng thư theo thumbprint.");

        return found[0];
    }

    private static IX509Certificate[] BuildITextCertificateChain(X509Certificate2 cert)
    {
        IBouncyCastleFactory factory = BouncyCastleFactoryCreator.GetFactory();

        using var x509Chain = new X509Chain();
        x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        x509Chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

        _ = x509Chain.Build(cert);

        var list = new List<IX509Certificate>();

        if (x509Chain.ChainElements.Count > 0)
        {
            foreach (X509ChainElement el in x509Chain.ChainElements)
            {
                using var ms = new MemoryStream(el.Certificate.RawData);
                list.Add(factory.CreateX509Certificate(ms));
            }
        }
        else
        {
            using var ms = new MemoryStream(cert.RawData);
            list.Add(factory.CreateX509Certificate(ms));
        }

        return list.ToArray();
    }

    private static string NormalizeThumbprint(string? tp)
        => (tp ?? "").Replace(" ", "").Replace(":", "").Trim().ToUpperInvariant();
}

// ====== Models ======
public sealed class SignConfig
{
    public string? ccvThumbprint { get; set; }
    public string? tcThumbprint { get; set; }
}

public sealed class SaveConfigRequest
{
    [JsonPropertyName("ccvThumbprint")]
    public string ccvThumbprint { get; set; } = "";

    [JsonPropertyName("tcThumbprint")]
    public string tcThumbprint { get; set; } = "";
}

public sealed class SignRequest
{
    [JsonPropertyName("pdfBase64")]
    public string? PdfBase64 { get; set; }

    [JsonPropertyName("fieldName")]
    public string? FieldName { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("location")]
    public string? Location { get; set; }

    [JsonPropertyName("role")]
    public string? Role { get; set; } // "CCV" | "TC"

    [JsonPropertyName("appearancePngBase64")]
    public string? AppearancePngBase64 { get; set; } // data:image/png;base64,... hoặc base64

    // Vị trí ô ký
    [JsonPropertyName("pageNumber")]
    public int? PageNumber { get; set; }

    [JsonPropertyName("x")]
    public float? X { get; set; }

    [JsonPropertyName("y")]
    public float? Y { get; set; }

    [JsonPropertyName("w")]
    public float? W { get; set; }

    [JsonPropertyName("h")]
    public float? H { get; set; }
}

// ====== Token signature ======
public sealed class TokenExternalSignature : IExternalSignature
{
    private readonly RSA? _rsa;
    private readonly ECDsa? _ecdsa;

    public TokenExternalSignature(X509Certificate2 cert)
    {
        _rsa = cert.GetRSAPrivateKey();
        _ecdsa = cert.GetECDsaPrivateKey();

        if (_rsa == null && _ecdsa == null)
            throw new Exception("Không lấy được private key từ chứng thư (token/driver).");
    }

    public string GetDigestAlgorithmName() => "SHA256";

    public string GetSignatureAlgorithmName()
        => _rsa != null ? "RSA" : "ECDSA";

    public ISignatureMechanismParams? GetSignatureMechanismParameters() => null;

    public byte[] Sign(byte[] message)
    {
        if (_rsa != null)
            return _rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return _ecdsa!.SignData(message, HashAlgorithmName.SHA256);
    }
}
