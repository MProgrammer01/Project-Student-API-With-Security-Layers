using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using StudentApi.DataSimulation;
using StudentApi.Model;
using StudentApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;


namespace StudentApi.Controllers
{

    // This controller is responsible for authentication-related actions,
    // such as logging in and issuing JWT tokens.
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IConfiguration configuration, ILogger<AuthController> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }


        // This endpoint handles user login.
        // It verifies credentials and returns a JWT token if login succeeds.
        [HttpPost("login")]
        [EnableRateLimiting("AuthLimiter")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // ✅ Capture caller IP once (used in all logs for tracing)
            // 📌 We store IP as a string and default to "unknown" to avoid null issues.
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";


            // Step 1: Find the student by email from the in-memory data store.
            // Email acts as the unique login identifier.
            var student = StudentDataSimulation.StudentsList
                .FirstOrDefault(s => s.Email == request.Email);


            // If no student is found with the given email,
            // return 401 Unauthorized without revealing which field was wrong.
            if (student == null)
            {
                _logger.LogWarning(
                    "Failed login attempt (email not found). Email={Email}, IP={IP}",
                    request.Email,
                    ip
                );

                // Return generic message to avoid revealing whether email exists.
                return Unauthorized("Invalid credentials");
            }

            // Step 2: Verify the provided password against the stored hash.
            // BCrypt handles hashing and salt internally.
            bool isValidPassword =
                BCrypt.Net.BCrypt.Verify(request.Password, student.PasswordHash);


            // If the password does not match the stored hash,
            // return 401 Unauthorized.
            if (!isValidPassword)
            {
                _logger.LogWarning(
                    "Failed login attempt (bad password). Email={Email}, IP={IP}",
                    request.Email,
                    ip
                );

                // Return generic message to avoid revealing which field is wrong.
                return Unauthorized("Invalid credentials");
            }


            // Step 3: Create claims that represent the authenticated user's identity.
            // These claims will be embedded inside the JWT.
            var claims = new[]
            {
                // Unique identifier for the student
                new Claim(ClaimTypes.NameIdentifier, student.Id.ToString()),


                // Student email address
                new Claim(ClaimTypes.Email, student.Email),


                // Role (Student or Admin) used later for authorization
                new Claim(ClaimTypes.Role, student.Role)
            };

            // Move secretKey retrieval here, after _configuration is available
            var secretKey = _configuration["JWT_SECRET_KEY"];

            if (string.IsNullOrWhiteSpace(secretKey))
            {
                throw new Exception("JWT secret key is not configured.");
            }
            // Step 4: Create the symmetric security key used to sign the JWT.
            // This key must match the key used in JWT validation middleware.
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(secretKey));


            // Step 5: Define the signing credentials.
            // This specifies the algorithm used to sign the token.
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);


            // Step 6: Create the JWT token.
            // The token includes issuer, audience, claims, expiration, and signature.
            var token = new JwtSecurityToken(
                issuer: "StudentApi",
                audience: "StudentApiUsers",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds
            );


            var accessToken = new JwtSecurityTokenHandler().WriteToken(token);

            // Create refresh token (random)
            var refreshToken = GenerateRefreshToken();

            // Store refresh token securely (hash + expiry + not revoked)
            student.RefreshTokenHash = BCrypt.Net.BCrypt.HashPassword(refreshToken);
            student.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7);
            student.RefreshTokenRevokedAt = null;

            // ===============================
            // Step 10: Optional success log (low noise) do this in specific cases
            // ===============================
            // ✅ Safe success log: user ID + email + IP only (NO tokens)
            // 📌 Useful for later investigations (timeline reconstruction).
            _logger.LogInformation(
                "Successful login. UserId={UserId}, Email={Email}, IP={IP}",
                student.Id,
                student.Email,
                ip
            );

            return Ok(new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });



        }

        [HttpPost("refresh")]
        [EnableRateLimiting("AuthLimiter")]
        public IActionResult Refresh([FromBody] RefreshRequest request)
        {
            // ✅ Capture caller IP once (used in all logs for tracing)
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var student = StudentDataSimulation.StudentsList
                .FirstOrDefault(s => s.Email == request.Email);

            if (student == null)
            {
                _logger.LogWarning(
                    "Invalid refresh attempt (email not found). Email={Email}, IP={IP}",
                    request.Email,
                    ip
                );

                return Unauthorized("Invalid refresh request");
            }

            if (student.RefreshTokenRevokedAt != null)
            {
                _logger.LogWarning(
                    "Refresh attempt using revoked token. UserId={UserId}, Email={Email}, IP={IP}",
                    student.Id,
                    student.Email,
                    ip
                );

                return Unauthorized("Refresh token is revoked");
            }


            if (student.RefreshTokenExpiresAt == null || student.RefreshTokenExpiresAt <= DateTime.UtcNow)
            {
                _logger.LogWarning(
                    "Refresh attempt using expired token. UserId={UserId}, Email={Email}, IP={IP}",
                    student.Id,
                    student.Email,
                    ip
                );

                return Unauthorized("Refresh token expired");
            }

            bool refreshValid = BCrypt.Net.BCrypt.Verify(request.RefreshToken, student.RefreshTokenHash);
            if (!refreshValid)
            {
                _logger.LogWarning(
                    "Invalid refresh token attempt. UserId={UserId}, Email={Email}, IP={IP}",
                    student.Id,
                    student.Email,
                    ip
                );

                return Unauthorized("Invalid refresh token");
            }

            // Issue NEW access token (same claims & signing settings as login)
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, student.Id.ToString()),
                new Claim(ClaimTypes.Email, student.Email),
                new Claim(ClaimTypes.Role, student.Role)
            };

            // Move secretKey retrieval here, after _configuration is available
            var secretKey = _configuration["JWT_SECRET_KEY"];

            if (string.IsNullOrWhiteSpace(secretKey))
            {
                throw new Exception("JWT secret key is not configured.");
            }

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(secretKey));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var jwt = new JwtSecurityToken(
                issuer: "StudentApi",
                audience: "StudentApiUsers",
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            var newAccessToken = new JwtSecurityTokenHandler().WriteToken(jwt);

            // Rotation: replace refresh token
            var newRefreshToken = GenerateRefreshToken();
            student.RefreshTokenHash = BCrypt.Net.BCrypt.HashPassword(newRefreshToken);
            student.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7);
            student.RefreshTokenRevokedAt = null;

            // ✅ Optional low-noise success log (safe)
            _logger.LogInformation(
                "Refresh succeeded. UserId={UserId}, Email={Email}, IP={IP}",
                student.Id,
                student.Email,
                ip
            );

            return Ok(new TokenResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        [HttpPost("logout")]
        public IActionResult Logout([FromBody] LogoutRequest request)
        {
            var student = StudentDataSimulation.StudentsList
                .FirstOrDefault(s => s.Email == request.Email);

            if (student == null)
                return Ok(); // Do not reveal if user exists

            bool refreshValid = BCrypt.Net.BCrypt.Verify(request.RefreshToken, student.RefreshTokenHash);
            if (!refreshValid)
                return Ok();

            student.RefreshTokenRevokedAt = DateTime.UtcNow;
            return Ok("Logged out successfully");
        }


        private static string GenerateRefreshToken()
        {
            var bytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

    }
}