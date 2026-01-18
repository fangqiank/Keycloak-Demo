using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Scalar.AspNetCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = context =>
            {
                context.Response.Redirect("/login");
                return Task.CompletedTask;
            }
        };
    })
    .AddOpenIdConnect(options =>
    {
        var keycloakConfig = builder.Configuration.GetSection("Keycloak");

        options.Authority = keycloakConfig["Authority"];
        options.ClientId = keycloakConfig["ClientId"];
        options.ClientSecret = keycloakConfig["ClientSecret"];

        options.ResponseType = OpenIdConnectResponseType.Code;

        options.UsePkce = true;

        options.SaveTokens = true;

        options.GetClaimsFromUserInfoEndpoint = true;
        
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");

        options.RequireHttpsMetadata = false;

        options.CallbackPath = new PathString("/signin-oidc");
        options.SignedOutCallbackPath = new PathString("/signout-callback-oidc");

        options.RemoteSignOutPath = new PathString("/signout-oidc");

        options.ClaimActions.MapJsonKey("preferred_username", "preferred_username");
        options.ClaimActions.MapJsonKey("email_verified", "email_verified");

        options.Events = new OpenIdConnectEvents
        {
            OnTokenValidated = context =>
            {
                Console.WriteLine($"Token validated for user: {context.Principal?.Identity?.Name}");
                return Task.CompletedTask;
            },

            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                context.Response.Redirect("/error");
                context.HandleResponse();
                return Task.CompletedTask;
            },

            OnAuthorizationCodeReceived = context =>
            {
                Console.WriteLine("Authorization code received.");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AuthenticatedUser", policy =>
        policy.RequireAuthenticatedUser());

    options.AddPolicy("RequireEmail", policy =>
        policy.RequireClaim(ClaimTypes.Email));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();


app.MapGet("/", () =>
{
    return Results.Content("""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Keycloak .NET 10 Demo</title>
        <style>
            :root {
                --primary: #4f46e5;
                --primary-hover: #4338ca;
                --bg: #f8fafc;
                --card-bg: #ffffff;
                --text-main: #1e293b;
                --text-muted: #64748b;
            }
            body { 
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; 
                margin: 0; 
                background-color: var(--bg);
                color: var(--text-main);
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }
            .container { 
                max-width: 600px; 
                width: 90%;
                background: var(--card-bg);
                padding: 3rem;
                border-radius: 1.5rem;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
                text-align: center;
            }
            h1 { 
                font-size: 2.25rem; 
                font-weight: 800; 
                margin-bottom: 1rem;
                background: linear-gradient(to right, #4f46e5, #06b6d4);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            p { color: var(--text-muted); line-height: 1.6; margin-bottom: 2rem; }
            .menu { 
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 1rem;
                margin-top: 2rem;
            }
            .menu a { 
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 0.75rem 1rem; 
                background: white; 
                color: var(--text-main); 
                text-decoration: none; 
                border-radius: 0.75rem; 
                font-weight: 600;
                border: 1px solid #e2e8f0;
                transition: all 0.2s;
            }
            .menu a:hover { 
                border-color: var(--primary);
                color: var(--primary);
                transform: translateY(-2px);
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }
            .menu a.primary {
                background: var(--primary);
                color: white;
                border-color: var(--primary);
            }
            .menu a.primary:hover {
                background: var(--primary-hover);
                color: white;
            }
            code { 
                background: #f1f5f9; 
                padding: 0.2rem 0.4rem; 
                border-radius: 0.25rem; 
                font-size: 0.875rem;
                color: #ef4444;
            }
            .footer { margin-top: 3rem; font-size: 0.875rem; color: var(--text-muted); }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Keycloak Demo</h1>
            <p>基于 <strong>.NET 10 Minimal API</strong> 的企业级身份认证示例方案。</p>
            
            <div class="menu">
                <a href="/login" class="primary">立即登录</a>
                <a href="/user-info">用户信息</a>
                <a href="/api/public">公开 API</a>
                <a href="/api/secure">受保护 API</a>
            </div>

            <div class="footer">
                <p>后端服务状态: <code>http://localhost:8081</code></p>
                <a href="/logout" style="color: #94a3b8; text-decoration: none;">安全退出系统</a>
            </div>
        </div>
    </body>
    </html>
    """, "text/html");
}).WithName("Home");

app.MapGet("/login", async context =>
{
    if(context.User.Identity?.IsAuthenticated == true)
    {
        context.Response.Redirect("/");
        return;
    }

    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, 
        new AuthenticationProperties
        {
            RedirectUri = "/"
        });
}).WithName("Login");

app.MapGet("/user-info", async (HttpContext context) =>
{
    if(context.User.Identity?.IsAuthenticated != true)
        return Results.Redirect("/login");

    var claims = context.User.Claims.Select(c => new { c.Type, c.Value });
    var token = await context.GetTokenAsync("access_token");
    var idToken = await context.GetTokenAsync("id_token");
    var refreshToken = await context.GetTokenAsync("refresh_token");

    var claimsRows = string.Join("", claims.Select(c =>
        $"<tr><td>{c.Type}</td><td>{c.Value}</td></tr>"));

    var html = $$"""
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>用户信息 - Keycloak</title>
            <style>
                :root {
                    --primary: #4f46e5;
                    --primary-hover: #4338ca;
                    --bg: #f1f5f9;
                    --card-bg: #ffffff;
                    --text-main: #1e293b;
                    --text-muted: #64748b;
                    --border: #e2e8f0;
                }
                body {
                    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                    margin: 0;
                    background-color: var(--bg);
                    color: var(--text-main);
                    padding: 2rem 1rem;
                }
                .container {
                    max-width: 1000px;
                    margin: 0 auto;
                }
                .header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 2rem;
                }
                h1 { font-size: 1.5rem; margin: 0; font-weight: 700; color: var(--text-main); }
                .card {
                    background: var(--card-bg);
                    border-radius: 1rem;
                    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
                    padding: 1.5rem;
                    margin-bottom: 1.5rem;
                    border: 1px solid var(--border);
                }
                .card h2 {
                    font-size: 1.1rem;
                    margin-top: 0;
                    margin-bottom: 1.25rem;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    color: var(--primary);
                }
                .grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 1.5rem;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 0.9rem;
                }
                th {
                    text-align: left;
                    padding: 0.75rem;
                    background: #f8fafc;
                    border-bottom: 2px solid var(--border);
                    color: var(--text-muted);
                }
                td {
                    padding: 0.75rem;
                    border-bottom: 1px solid var(--border);
                }
                pre {
                    background: #1e293b;
                    color: #e2e8f0;
                    padding: 1rem;
                    border-radius: 0.5rem;
                    font-size: 0.8rem;
                    overflow-x: auto;
                    margin: 0;
                    max-height: 300px;
                }
                .btn {
                    display: inline-flex;
                    align-items: center;
                    padding: 0.5rem 1rem;
                    background: var(--primary);
                    color: white;
                    text-decoration: none;
                    border-radius: 0.5rem;
                    font-size: 0.875rem;
                    font-weight: 500;
                    border: none;
                    cursor: pointer;
                    transition: background 0.2s;
                }
                .btn:hover { background: var(--primary-hover); }
                .btn-outline {
                    background: transparent;
                    border: 1px solid var(--border);
                    color: var(--text-main);
                }
                .btn-outline:hover { background: #f8fafc; border-color: var(--text-muted); }
                .badge {
                    padding: 0.25rem 0.5rem;
                    border-radius: 9999px;
                    font-size: 0.75rem;
                    font-weight: 600;
                    background: #dcfce7;
                    color: #166534;
                }
                details { margin-top: 1rem; border-top: 1px solid var(--border); padding-top: 1rem; }
                summary { cursor: pointer; color: var(--text-muted); font-size: 0.875rem; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 身份面板</h1>
                    <div>
                        <a href="/" class="btn btn-outline">🏠 首页</a>
                        <a href="/logout" class="btn" style="background: #ef4444;">🚪 退出</a>
                    </div>
                </div>
        
                <div class="card">
                    <h2>📋 基本信息 <span class="badge">已验证</span></h2>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
                        <div>
                            <div style="font-size: 0.75rem; color: var(--text-muted);">当前用户</div>
                            <div style="font-weight: 600;">{{context.User.Identity?.Name ?? "未知"}}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.75rem; color: var(--text-muted);">认证方式</div>
                            <div style="font-weight: 600;">{{context.User.Identity?.AuthenticationType ?? "OIDC"}}</div>
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr><th>声明类型 (Claim Type)</th><th>声明值 (Value)</th></tr>
                        </thead>
                        <tbody>{{claimsRows}}</tbody>
                    </table>
                </div>
        
                <div class="grid">
                    <div class="card">
                        <h2>🔑 Access Token</h2>
                        <pre>{{FormatToken(token)}}</pre>
                        <button class="btn" style="margin-top: 1rem; width: 100%;" onclick="copyToClipboard('{{token}}')">复制 Token</button>
                    </div>
                    <div class="card">
                        <h2>🆔 ID Token</h2>
                        <pre>{{FormatToken(idToken)}}</pre>
                        <button class="btn" style="margin-top: 1rem; width: 100%;" onclick="copyToClipboard('{{idToken}}')">复制 ID Token</button>
                    </div>
                </div>
        
                <div class="card" style="margin-top: 1.5rem;">
                    <details>
                        <summary>查看高级调试数据</summary>
                        <div style="padding-top: 1rem; font-size: 0.8rem; color: var(--text-muted);">
                            <p><strong>Raw Access Token:</strong> <code style="word-break: break-all;">{{token}}</code></p>
                            <p><strong>Raw Refresh Token:</strong> <code style="word-break: break-all;">{{refreshToken}}</code></p>
                        </div>
                    </details>
                </div>
            </div>
    
            <script>
                function copyToClipboard(text) {
                    if (!text) return;
                    navigator.clipboard.writeText(text).then(() => {
                        alert('✅ 已复制到剪贴板');
                    });
                }
            </script>
        </body>
        </html>
    """;

    return Results.Content(html, "text/html");
})
    .WithName("UserInfo")
    .RequireAuthorization();

string FormatToken(string? token)
{
    if (string.IsNullOrEmpty(token) || !token.Contains('.'))
        return "无效的令牌";
    try
    {
        var handler = new JwtSecurityTokenHandler();
        if (handler.CanReadToken(token))
        {
            var jwtToken = handler.ReadJwtToken(token);

            var header = JsonSerializer.Serialize(
                JsonSerializer.Deserialize<Dictionary<string, object>>(
                    Base64UrlDecode(jwtToken.RawHeader)),
                new JsonSerializerOptions { WriteIndented = true });

            var payload = JsonSerializer.Serialize(
                JsonSerializer.Deserialize<Dictionary<string, object>>(
                    Base64UrlDecode(jwtToken.RawPayload)),
                new JsonSerializerOptions { WriteIndented = true });

            return $"Header:\n{header}\n\nPayload:\n{payload}\n\n签名: {jwtToken.RawSignature.Substring(0, 20)}...";
        }
    }
    catch
    {
        // 如果无法解析为 JWT，返回原始令牌
    }

    return token.Length > 100 ? token.Substring(0, 100) + "..." : token;
}
string Base64UrlDecode(string base64Url)
{
    string base64 = base64Url.Replace('-', '+').Replace('_', '/');
    switch (base64.Length % 4)
    {
        case 2: base64 += "=="; break;
        case 3: base64 += "="; break;
    }
    var bytes = Convert.FromBase64String(base64);
    return System.Text.Encoding.UTF8.GetString(bytes);
}

app.MapGet("api/public", () =>
{
       return Results.Ok(new 
       { 
           Message = "这是一个公开的 API 端点，任何人都可以访问。",
           Timestamp = DateTime.UtcNow,
           Status = "公开访问"
       });

}).WithName("PublicApi");

app.MapGet("api/secure", (HttpContext context) =>
{
    var user = context.User;
    return Results.Ok(new 
    { 
        Message = "这是一个受保护的 API 端点，只有经过身份验证的用户才能访问。",
        User = user.Identity?.Name,
        Claims = user.Claims.Select(c => new { c.Type, c.Value }),
        Timestamp = DateTime.UtcNow,
        Status = "受保护访问"
    });
})
    .WithName("SecureApi")
    .RequireAuthorization("AuthenticatedUser");

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    var logoutUrl = $"{builder.Configuration["Keycloak:Authority"]}/protocol/openid-connect/logout";

    return Results.Content($$$"""
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>已登出 - Keycloak</title>
            <style>
                body { 
                    font-family: 'Segoe UI', system-ui, sans-serif; 
                    margin: 0; background: #f8fafc; color: #1e293b;
                    display: flex; align-items: center; justify-content: center; min-height: 100vh;
                }
                .card {
                    background: white; padding: 3rem; border-radius: 1.5rem; text-align: center;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.05); max-width: 400px; width: 90%;
                }
                h1 { color: #4f46e5; margin-bottom: 1rem; }
                p { color: #64748b; margin-bottom: 2rem; }
                .btn {
                    display: block; padding: 0.75rem; background: #4f46e5; color: white;
                    text-decoration: none; border-radius: 0.75rem; font-weight: 600; margin-bottom: 0.5rem;
                }
                .btn-secondary { background: #f1f5f9; color: #475569; }
            </style>
        </head>
        <body>
            <div class="card">
                <div style="font-size: 3rem; margin-bottom: 1rem;">👋</div>
                <h1>已安全退出</h1>
                <p>您已成功退出应用程序。为了彻底安全，建议您同时退出身份认证中心。</p>
                <a href="{logoutUrl}" class="btn">彻底退出 Keycloak</a>
                <a href="/" class="btn btn-secondary">返回首页</a>
            </div>
        </body>
        </html>
        """, "text/html");
})
    .WithName("Logout");

app.MapGet("/error", () =>
{
    return Results.Content("""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>认证错误</title>
        <style>
            body { 
                font-family: 'Segoe UI', system-ui, sans-serif; 
                margin: 0; background: #fff1f2; color: #991b1b;
                display: flex; align-items: center; justify-content: center; min-height: 100vh;
            }
            .card {
                background: white; padding: 3rem; border-radius: 1.5rem; text-align: center;
                box-shadow: 0 10px 25px rgba(0,0,0,0.05); max-width: 400px; width: 90%;
                border: 1px solid #fecdd3;
            }
            h1 { color: #e11d48; margin-bottom: 1rem; }
            p { color: #9f1239; margin-bottom: 2rem; opacity: 0.8; }
            .btn {
                display: block; padding: 0.75rem; background: #e11d48; color: white;
                text-decoration: none; border-radius: 0.75rem; font-weight: 600;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <div style="font-size: 3rem; margin-bottom: 1rem;">⚠️</div>
            <h1>认证失败</h1>
            <p>在登录过程中发生了一些错误，可能是配置不当或会话已超时。</p>
            <a href="/" class="btn">尝试重新登录</a>
        </div>
    </body>
    </html>
    """, "text/html");
});

app.MapGet("/signin-oidc", () => Results.Redirect("/"));
app.MapGet("/signout-oidc", () => Results.Redirect("/"));

app.Run();


