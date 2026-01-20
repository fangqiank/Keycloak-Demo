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

## 认证配置详解

### OIDC 配置参数（Program.cs:36-90）

| 参数 | 当前配置 | 说明 |
|------|----------|------|
| `Authority` | 从配置读取 | Keycloak realm 地址 |
| `ClientId` | 从配置读取 | 客户端 ID |
| `ClientSecret` | 从配置读取 | 空（public client） |
| `ResponseType` | `code` | 授权码模式 |
| `UsePkce` | `true` | 启用 PKCE |
| `SaveTokens` | `true` | 保存 token 到 Cookie |
| `RequireHttpsMetadata` | `false` | 开发环境禁用 HTTPS |

### MetadataAddress 和 ValidIssuer

**当前配置：** 这两个参数未手动配置，自动从 `Authority` 推断。

| 参数 | 自动值 | 说明 |
|------|--------|------|
| `MetadataAddress` | `{Authority}/.well-known/openid-configuration` | OIDC 元数据地址 |
| `ValidIssuer` | `{Authority}` | Token issuer 验证 |

**何时需要手动配置：**
- 元数据地址非标准时设置 `MetadataAddress`
- 需要 issuer 验证时配置 `TokenValidationParameters.ValidIssuer`

## Keycloak 数据库查询

### PostgreSQL 连接信息

```
Host: 192.168.1.25:5432
Database: postgres
Username: postgres
```

### Keycloak + PostgreSQL 连接配置

#### 方式 1：Docker 环境变量方式

```bash
# 启动 PostgreSQL
docker run -d --name keycloak-db \
  -e POSTGRES_DB=keycloak \
  -e POSTGRES_USER=keycloak \
  -e POSTGRES_PASSWORD=password \
  postgres:16

# 启动 Keycloak 并连接 PostgreSQL
docker run -d --name keycloak \
  -p 8080:8080 \
  -e KC_DB=postgres \
  -e KC_DB_URL=jdbc:postgresql://192.168.1.25:5432/postgres \
  -e KC_DB_USERNAME=postgres \
  -e KC_DB_PASSWORD=postgres \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.5.1 start-dev
```

#### 方式 2：Docker Compose 方式（推荐）

创建 `docker-compose.yml`：

```yaml
version: '3.8'
services:
  postgres:
    image: postgres:16
    container_name: keycloak-db
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  keycloak:
    image: quay.io/keycloak/keycloak:26.5.1
    container_name: keycloak
    command: start-dev
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: password
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: admin
    ports:
      - "8080:8080"
    depends_on:
      - postgres

volumes:
  postgres_data:
```

启动：
```bash
docker-compose up -d
```

#### Keycloak 数据库环境变量说明

| 变量 | 说明 | 示例值 |
|------|------|--------|
| `KC_DB` | 数据库类型 | `postgres` |
| `KC_DB_URL` | JDBC 连接 URL | `jdbc:postgresql://host:port/database` |
| `KC_DB_USERNAME` | 数据库用户名 | `postgres` |
| `KC_DB_PASSWORD` | 数据库密码 | `postgres` |
| `KC_DB_SCHEMA` | 数据库 schema（可选） | `public` |

### 常用表结构

| 表名 | 说明 |
|------|------|
| `REALM` | Realm 信息 |
| `USER_ENTITY` | 用户基本信息 |
| `USER_ATTRIBUTE` | 用户扩展属性 |
| `CREDENTIAL` | 用户凭证（密码等） |
| `CLIENT` | 客户端信息 |
| `USER_ROLE_MAPPING` | 用户角色映射 |

### 常用查询示例

```sql
-- 查看所有 Realm
SELECT id, name FROM REALM;

-- 查看 myrealm 的用户
SELECT id, username, email, created_timestamp
FROM USER_ENTITY
WHERE REALM_ID = (SELECT id FROM REALM WHERE name = 'myrealm');

-- 查看用户属性
SELECT u.USERNAME, ua.NAME, ua.VALUE
FROM USER_ENTITY u
JOIN USER_ATTRIBUTE ua ON u.ID = ua.USER_ID
WHERE u.REALM_ID = '<realm-id>';

-- 查看客户端
SELECT CLIENT_ID, PROTOCOL
FROM CLIENT
WHERE REALM_ID = '<realm-id>';
```

## 常见问题排查

### 1. 无法连接 Keycloak

```powershell
# 测试 Keycloak 服务
curl.exe http://192.168.1.30:8080/

# 测试 realm 配置
curl.exe http://192.168.1.30:8080/realms/myrealm/.well-known/openid-configuration

# 检查 Docker 容器
docker ps
```

### 2. redirect_uri 错误

确认 Keycloak Client 配置：
- `Valid redirect URIs`: `https://localhost:5001/signin-oidc` 或 `https://localhost:5001/*`
- `Valid post logout redirect URIs`: `https://localhost:5001/signout-callback-oidc`
- `Web origins`: `https://localhost:5001`

### 3. 认证失败

检查 Keycloak Client：
- `Client authentication`: OFF（public client）
- `Standard flow`: ON

### 4. DefaultSignInScheme 错误

确保 `AddAuthentication` 配置包含：
```csharp
options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
```
