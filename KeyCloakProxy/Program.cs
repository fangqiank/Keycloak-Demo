using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddOpenApi();
builder.Services.AddHttpClient();

// Configure HttpClient with timeout for Keycloak
builder.Services.AddHttpClient("Keycloak", client =>
{
    client.Timeout = TimeSpan.FromMinutes(2);
});

// Keycloak configuration
var keycloakAuthority = builder.Configuration["Keycloak:Authority"]
    ?? throw new InvalidOperationException("Keycloak:Authority is not configured");
var keycloakMetadataAddress = builder.Configuration["Keycloak:MetadataAddress"]
    ?? $"{keycloakAuthority}/.well-known/openid-configuration";
var keycloakValidIssuer = builder.Configuration["Keycloak:ValidIssuer"]
    ?? keycloakAuthority;
var keycloakAudience = builder.Configuration["Keycloak:Audience"]
    ?? throw new InvalidOperationException("Keycloak:Audience is not configured");
var keycloakClientId = builder.Configuration["Keycloak:ClientId"]
    ?? throw new InvalidOperationException("Keycloak:ClientId is not configured");
var keycloakClientSecret = builder.Configuration["Keycloak:ClientSecret"];
var requireHttpsMetadata = builder.Configuration.GetValue<bool>("Keycloak:RequireHttpsMetadata");

// Build token endpoint URL
var keycloakTokenEndpoint = $"{keycloakAuthority}/protocol/openid-connect/token";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = keycloakAuthority;
        options.MetadataAddress = keycloakMetadataAddress;
        options.Audience = keycloakAudience;
        options.RequireHttpsMetadata = requireHttpsMetadata;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = keycloakValidIssuer,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidAudience = keycloakAudience,
            // Keycloak claims mapping
            NameClaimType = "preferred_username",
            RoleClaimType = "resource_access"
        };
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"[Auth Failed] {context.Exception.Message}");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine("[Auth Success] Token validated");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    // Policy requiring Admin role
    options.AddPolicy("AdminOnly", policy =>
        policy.AddRequirements(new KeycloakRoleRequirement("Admin")));

    // Policy requiring Admin or User role
    options.AddPolicy("UserOrAdmin", policy =>
        policy.AddRequirements(new KeycloakRoleRequirement("Admin", "User")));
});

builder.Services.AddSingleton<IAuthorizationHandler, KeycloakRoleHandler>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.WithTheme(ScalarTheme.Mars);
    });
}

app.UseHttpsRedirection();

// Enable static files for frontend
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// API health check endpoint
app.MapGet("/api/health", () => new
{
    message = "Keycloak Proxy API",
    status = "running",
    timestamp = DateTime.Now
});

// Fallback to index.html for SPA routes
app.MapFallbackToFile("index.html");

// API endpoints - prefixed with /api

// Token exchange endpoint
app.MapPost("/auth/token", async (
    TokenRequest request, 
    IHttpClientFactory httpClientFactory, 
    CancellationToken ct) =>
{
    var httpClient = httpClientFactory.CreateClient();

    var formData = new Dictionary<string, string>
    {
        { "grant_type", "password" },
        { "client_id", keycloakClientId },
        { "username", request.Username },
        { "password", request.Password }
    };

    if (!string.IsNullOrEmpty(keycloakClientSecret))
    {
        formData["client_secret"] = keycloakClientSecret;
    }

    var response = await httpClient.PostAsync(
        keycloakTokenEndpoint, 
        new FormUrlEncodedContent(formData), 
        ct);

    if (!response.IsSuccessStatusCode)
    {
        var errorContent = await response.Content.ReadAsStringAsync(ct);
        return Results.UnprocessableEntity(new { 
            error = "Token acquisition failed", 
            details = errorContent });
    }

    var content = await response.Content.ReadAsStringAsync(ct);
    var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(content, new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true
    });

    return Results.Ok(tokenResponse);
})
.Accepts<TokenRequest>("application/json")
.Produces<TokenResponse>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status422UnprocessableEntity);

// OAuth2 callback endpoint - exchanges authorization code for tokens
app.MapPost("/api/auth/callback", async (
    CallbackRequest request,
    IHttpClientFactory httpClientFactory,
    CancellationToken ct) =>
{
    try
    {
        Console.WriteLine($"[Callback] Exchanging code for token...");
        Console.WriteLine($"[Callback] Token endpoint: {keycloakTokenEndpoint}");

        var httpClient = httpClientFactory.CreateClient("Keycloak");

        var formData = new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "client_id", keycloakClientId },
            { "code", request.Code },
            { "redirect_uri", request.RedirectUri },
            { "code_verifier", request.CodeVerifier }
        };

        if (!string.IsNullOrEmpty(keycloakClientSecret))
        {
            formData["client_secret"] = keycloakClientSecret;
        }

        Console.WriteLine($"[Callback] Sending request to Keycloak...");

        var response = await httpClient.PostAsync(
            keycloakTokenEndpoint,
            new FormUrlEncodedContent(formData),
            CancellationToken.None);

        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(CancellationToken.None);
            return Results.UnprocessableEntity(new
            {
                error = "Token exchange failed",
                details = errorContent,
                endpoint = keycloakTokenEndpoint
            });
        }

        var content = await response.Content.ReadAsStringAsync(CancellationToken.None);

        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(content, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.access_token))
        {
            return Results.UnprocessableEntity(new
            {
                error = "No access_token in Keycloak response",
                rawResponse = content
            });
        }

        return Results.Ok(tokenResponse);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Callback] Exception: {ex.Message}");
        Console.WriteLine($"[Callback] Stack trace: {ex.StackTrace}");
        return Results.UnprocessableEntity(new
        {
            error = "Token exchange failed",
            message = ex.Message,
            endpoint = keycloakTokenEndpoint
        });
    }
})
.Accepts<CallbackRequest>("application/json")
.Produces<TokenResponse>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status422UnprocessableEntity);

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

// Manual token validation endpoint
app.MapPost("/auth/validate", async (
    ValidateTokenRequest request,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.Token))
    {
        return Results.BadRequest(new { error = "Token is required" });
    }

    try
    {
        // Fetch OpenID Connect configuration to get signing keys
        var documentRetriever = new HttpDocumentRetriever { RequireHttps = false };
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{keycloakAuthority}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            documentRetriever);

        var openIdConfig = await configurationManager.GetConfigurationAsync(ct);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = keycloakAuthority,
            ValidateAudience = true,
            ValidAudience = keycloakAudience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = openIdConfig.SigningKeys,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        // Validate token and read claims
        var principal = tokenHandler.ValidateToken(
            request.Token,
            validationParameters,
            out var validatedToken);

        var jwtToken = validatedToken as JwtSecurityToken;

        var result = new TokenValidationResult
        {
            Valid = true,
            Subject = principal.FindFirst("sub")?.Value,
            Username = principal.FindFirst("preferred_username")?.Value,
            Email = principal.FindFirst("email")?.Value,
            Issuer = principal.FindFirst("iss")?.Value,
            Audience = principal.FindFirst("aud")?.Value,
            ExpiresAt = jwtToken?.ValidTo,
            IssuedAt = jwtToken?.ValidFrom,
            ExpiresIn = jwtToken?.ValidTo != null
                ? (long)(jwtToken.ValidTo - DateTime.UtcNow).TotalSeconds
                : null,
            Claims = principal.Claims
                .Select(c => (object)new { c.Type, c.Value })
                .ToList()
        };

        return Results.Ok(result);
    }
    catch (SecurityTokenExpiredException)
    {
        return Results.UnprocessableEntity(new TokenValidationResult
        {
            Valid = false,
            Error = "TokenExpired",
            ErrorDescription = "The token has expired"
        });
    }
    catch (SecurityTokenInvalidIssuerException ex)
    {
        return Results.UnprocessableEntity(new TokenValidationResult
        {
            Valid = false,
            Error = "InvalidIssuer",
            ErrorDescription = ex.Message
        });
    }
    catch (SecurityTokenInvalidSignatureException)
    {
        return Results.UnprocessableEntity(new TokenValidationResult
        {
            Valid = false,
            Error = "InvalidSignature",
            ErrorDescription = "The token signature is invalid"
        });
    }
    catch (SecurityTokenValidationException ex)
    {
        return Results.UnprocessableEntity(new TokenValidationResult
        {
            Valid = false,
            Error = "ValidationError",
            ErrorDescription = ex.Message
        });
    }
    catch (Exception ex)
    {
        return Results.UnprocessableEntity(new TokenValidationResult
        {
            Valid = false,
            Error = "UnknownError",
            ErrorDescription = ex.Message
        });
    }
})
.Accepts<ValidateTokenRequest>("application/json")
.Produces<TokenValidationResult>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status422UnprocessableEntity);

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.RequireAuthorization();

// Role-based endpoints

// View current user roles
app.MapGet("/auth/roles", (HttpContext context) =>
{
    var user = context.User;

    // Get username from multiple possible claims
    var username = user.Identity?.Name
        ?? user.FindFirst("preferred_username")?.Value
        ?? user.FindFirst("sub")?.Value
        ?? user.FindFirst("email")?.Value
        ?? "unknown";

    // Extract roles from resource_access claim
    var resourceAccessClaim = user.FindFirst("resource_access")?.Value;
    List<string> roles = new();

    if (!string.IsNullOrEmpty(resourceAccessClaim))
    {
        try
        {
            using var jsonDoc = JsonDocument.Parse(resourceAccessClaim);
            if (jsonDoc.RootElement.TryGetProperty(keycloakClientId, out var clientAccess))
            {
                if (clientAccess.TryGetProperty("roles", out var rolesArray))
                {
                    foreach (var role in rolesArray.EnumerateArray())
                    {
                        roles.Add(role.GetString() ?? string.Empty);
                    }
                }
            }
        }
        catch
        {
            // JSON parse failed, return empty roles
        }
    }

    return Results.Ok(new
    {
        user = username,
        clientId = keycloakClientId,
        roles,
        // Debug info
        allClaims = user.Claims.Select(c => new { c.Type, c.Value })
    });
})
.WithName("GetUserRoles")
.RequireAuthorization();

// Admin only endpoint
app.MapGet("/api/admin", (HttpContext context) =>
{
    var user = context.User;

    // Get username
    var username = user.Identity?.Name
        ?? user.FindFirst("preferred_username")?.Value
        ?? user.FindFirst("sub")?.Value
        ?? "unknown";

    // Extract roles from resource_access
    var resourceAccessClaim = user.FindFirst("resource_access")?.Value;
    List<string> roles = new();

    if (!string.IsNullOrEmpty(resourceAccessClaim))
    {
        try
        {
            using var jsonDoc = JsonDocument.Parse(resourceAccessClaim);
            if (jsonDoc.RootElement.TryGetProperty(keycloakClientId, out var clientAccess))
            {
                if (clientAccess.TryGetProperty("roles", out var rolesArray))
                {
                    foreach (var role in rolesArray.EnumerateArray())
                    {
                        roles.Add(role.GetString() ?? string.Empty);
                    }
                }
            }
        }
        catch { }
    }

    return Results.Ok(new
    {
        message = "Admin access granted",
        user = username,
        roles,
        hasAdminRole = roles.Contains("Admin"),
        timestamp = DateTime.Now
    });
})
.WithName("AdminEndpoint")
.RequireAuthorization("AdminOnly");

// Dashboard endpoint (Admin or User)
app.MapGet("/api/dashboard", (HttpContext context) =>
{
    return Results.Ok(new
    {
        message = "Dashboard access granted",
        user = context.User.Identity?.Name,
        timestamp = DateTime.Now
    });
})
.WithName("DashboardEndpoint")
.RequireAuthorization("UserOrAdmin");

app.Run();

// Custom authorization requirement for Keycloak roles
class KeycloakRoleRequirement : IAuthorizationRequirement
{
    public string[] RequiredRoles { get; }
    public KeycloakRoleRequirement(params string[] roles) => RequiredRoles = roles;
}

class KeycloakRoleHandler : AuthorizationHandler<KeycloakRoleRequirement>
{
    private readonly IConfiguration _configuration;

    public KeycloakRoleHandler(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, KeycloakRoleRequirement requirement)
    {
        var clientId = _configuration["Keycloak:ClientId"] ?? string.Empty;
        var user = context.User;

        var resourceAccessClaim = user.FindFirst("resource_access")?.Value;

        if (string.IsNullOrEmpty(resourceAccessClaim))
        {
            return Task.CompletedTask;
        }

        try
        {
            using var jsonDoc = JsonDocument.Parse(resourceAccessClaim);
            if (jsonDoc.RootElement.TryGetProperty(clientId, out var clientAccess))
            {
                if (clientAccess.TryGetProperty("roles", out var rolesArray))
                {
                    var userRoles = new List<string>();
                    foreach (var role in rolesArray.EnumerateArray())
                    {
                        userRoles.Add(role.GetString() ?? string.Empty);
                    }

                    if (requirement.RequiredRoles.Any(role => userRoles.Contains(role, StringComparer.OrdinalIgnoreCase)))
                    {
                        context.Succeed(requirement);
                    }
                }
            }
        }
        catch (Exception)
        {
            // Silently fail on parse error for security
        }

        return Task.CompletedTask;
    }
}

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

internal record TokenRequest(string Username, string Password);

internal record CallbackRequest(string Code, string CodeVerifier, string RedirectUri);

internal record TokenResponse(
    string access_token,
    string token_type,
    int expires_in,
    int refresh_expires_in,
    string refresh_token,
    string scope,
    string? id_token
);

internal record ValidateTokenRequest(string Token);

internal record TokenValidationResult
{
    public required bool Valid { get; init; }
    public string? Subject { get; init; }
    public string? Username { get; init; }
    public string? Email { get; init; }
    public string? Issuer { get; init; }
    public string? Audience { get; init; }
    public DateTime? ExpiresAt { get; init; }
    public DateTime? IssuedAt { get; init; }
    public long? ExpiresIn { get; init; }
    public string? Error { get; init; }
    public string? ErrorDescription { get; init; }
    public List<object>? Claims { get; init; }
}
