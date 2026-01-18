# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

这是一个 .NET 10.0 Minimal API 演示项目，展示如何集成 Keycloak 作为 OpenID Connect 身份提供者。

**架构特点：**
- 单文件应用（Program.cs 包含所有逻辑）
- 使用 Cookie + OIDC 混合认证模式
- 内联 HTML 响应（无 Views/Controllers）
- PKCE 授权流程

## 常用命令

```powershell
# 构建项目
dotnet build

# 运行项目（开发环境）
dotnet run

# 运行项目（生产环境）
dotnet run --environment Production

# 发布
dotnet publish -c Release
```

## 配置说明

Keycloak 连接配置位于 `appsettings.json`：

```json
"Keycloak": {
  "Authority": "http://192.168.1.30/realms/demo",
  "ClientId": "public-client",
  "ClientSecret": ""
}
```

**注意：**
- Authority 应指向 Keycloak realm 的完整路径（包含 `/realms/{realm-name}`）
- 项目使用 public client（无需 ClientSecret）
- 开发环境配置在 `appsettings.Development.json` 中覆盖端口

## 认证流程架构

1. **认证管道**（Program.cs:16-85）
   - 默认方案：Cookie
   - Challenge 方案：OpenIDConnect
   - 回调路径：`/signin-oidc`

2. **Token 处理**
   - Access Token、ID Token、Refresh Token 均保存到 Cookie
   - 使用 `SaveTokens = true` 存储
   - 可通过 `context.GetTokenAsync("access_token")` 获取

3. **授权策略**
   - `AuthenticatedUser`：要求用户已登录
   - `RequireEmail`：要求用户包含 Email 声明

## 端点说明

| 端点 | 说明 | 保护级别 |
|------|------|----------|
| `/` | 首页 | 公开 |
| `/login` | 触发 OIDC Challenge | 公开（重定向到 Keycloak） |
| `/user-info` | 显示用户 Claims 和 Token | 需要认证 |
| `/api/public` | 公开 API | 公开 |
| `/api/secure` | 受保护 API | 需要认证 |
| `/logout` | 登出 | 公开 |
| `/error` | 认证错误页 | 公开 |

## 辅助函数

- `FormatToken(string? token)` (Program.cs:364)：JWT 解析和格式化
- `Base64UrlDecode(string base64Url)` (Program.cs:395)：Base64URL 解码

## 修改注意事项

1. **认证配置修改**：同步更新 `appsettings.json` 和 `appsettings.Development.json`
2. **添加新端点**：受保护端点需要添加 `.RequireAuthorization()`
3. **Claim 映射**：在 `options.ClaimActions.MapJsonKey()` 中添加新的 Claim 映射
4. **作用域**：修改 `options.Scope` 时需确保 Keycloak 客户端配置允许相应 Scope
