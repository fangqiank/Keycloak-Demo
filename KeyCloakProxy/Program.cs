using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
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

// Keycloak configuration
var keycloakAuthority = builder.Configuration["Keycloak:Authority"]
    ?? throw new InvalidOperationException("Keycloak:Authority is not configured");
var keycloakAudience = builder.Configuration["Keycloak:Audience"]
    ?? throw new InvalidOperationException("Keycloak:Audience is not configured");
var keycloakClientId = builder.Configuration["Keycloak:ClientId"]
    ?? throw new InvalidOperationException("Keycloak:ClientId is not configured");
var keycloakClientSecret = builder.Configuration["Keycloak:ClientSecret"];
var requireHttpsMetadata = builder.Configuration.GetValue<bool>("Keycloak:RequireHttpsMetadata");

// Extract realm from authority for token endpoint
var realm = keycloakAuthority.Split('/').Last();
var keycloakTokenEndpoint = keycloakAuthority.Replace($"/realms/{realm}", $"/realms/{realm}/protocol/openid-connect/token");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = keycloakAuthority;
        options.Audience = keycloakAudience;
        options.RequireHttpsMetadata = requireHttpsMetadata;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            // Allow token to not have audience (fallback to account)
            ValidAudience = keycloakAudience
        };
        options.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents
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

builder.Services.AddAuthorization();

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

app.UseAuthentication();
app.UseAuthorization();

// Public endpoint for testing
app.MapGet("/", () => new
{
    message = "Keycloak Proxy API",
    status = "running",
    endpoints = new[]
    {
        "/ - public health check",
        "/weatherforecast - requires authentication",
        "/auth/token - exchange username/password for access token",
        "/auth/validate - manual token validation"
    }
});

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

app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

internal record TokenRequest(string Username, string Password);

internal record TokenResponse(
    string access_token,
    string token_type,
    int expires_in,
    int refresh_expires_in,
    string refresh_token,
    string scope
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
