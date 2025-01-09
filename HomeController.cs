using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using ISLEMLER.Services;
using ISLEMLER.Events;
using ISLEMLER.Models;
using Npgsql;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace ISLEMLER.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class HomeController : ControllerBase
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;
        private readonly UserService _userService;

        public HomeController(IConfiguration configuration, UserService userService, ILogger<HomeController> logger)
        {
            _configuration = configuration;
            _userService = userService;
            _logger = logger;
            
            // Subscribe to UserCreated event
            _userService.UserCreated += HandleUserCreated;
        }

        private void HandleUserCreated(object? sender, UserEventArgs e)
        {
            _logger.LogInformation("New user created: {@UserEvent}", e);
        }

        [HttpPost]
        [Route("SendDataToDB")]
        public IActionResult SendDataToDB([FromBody] UserRequest request)
        {
            try
            {
                // Token'dan kullanıcı adını al
                var tokenUsername = User.Identity?.Name;
                _logger.LogInformation("Token username: {TokenUsername}", tokenUsername);

                if (string.IsNullOrEmpty(tokenUsername))
                {
                    _logger.LogError("No username found in token");
                    return Unauthorized("Invalid token");
                }

                // Token'daki kullanıcı adı ile gönderilen kullanıcı adı eşleşmeli
                if (tokenUsername.ToLower() != request.Username.ToLower())
                {
                    _logger.LogWarning("Username mismatch. Token: {TokenUsername}, Request: {RequestUsername}", 
                        tokenUsername, request.Username);
                    return BadRequest("Username mismatch with token");
                }

                if (request == null)
                {
                    return BadRequest("Request cannot be null");
                }

                _logger.LogInformation("SendDataToDB started with user details: {Username}", request.Username);

                if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
                {
                    _logger.LogWarning("Empty username or password submitted");
                    return BadRequest("Username and password are required");
                }

                // Kullanıcı bilgilerini kontrol et
             /*   if (request.Username != "birgul" || request.Password != "qwerty")
                {
                    _logger.LogWarning("Invalid credentials for user: {Username}", request.Username);
                    return BadRequest("Invalid username or password");
                }
*/
                var connectionString = _configuration.GetConnectionString("DefaultConnection");
                if (string.IsNullOrEmpty(connectionString))
                {
                    _logger.LogError("Database connection string not found");
                    return StatusCode(500, "Database connection string is missing");
                }

                // Create user event args first
                var userEvent = new UserEventArgs
                {
                    Username = request.Username,
                    Email = string.Empty,
                    Age = 33,
                    Timestamp = DateTime.Now
                };

                // Validate user event args
                if (userEvent == null)
                {
                    _logger.LogError("UserEventArgs is null");
                    return BadRequest("Invalid user event data");
                }

                // Log the user event details
                _logger.LogInformation("Created user event: {@UserEvent}", userEvent);

                _logger.LogInformation("Opening database connection...");

                using (var connection = new NpgsqlConnection(connectionString))
                {
                    try 
                    {
                        connection.Open();
                        _logger.LogInformation("Database connection successful");

                        using (var cmd = new NpgsqlCommand())
                        {
                            cmd.Connection = connection;
                            cmd.CommandText = "INSERT INTO \"SecondUsers\" (\"name\", \"email\", \"age\") VALUES (@name, @email, @age)";
                            cmd.Parameters.AddWithValue("name", userEvent.Username);
                            cmd.Parameters.AddWithValue("email", userEvent.Email);
                            cmd.Parameters.AddWithValue("age", userEvent.Age);
                            _logger.LogInformation("Executing SQL command: {SQL}", cmd.CommandText);
                            cmd.ExecuteNonQuery();
                        }
                    }
                    catch (NpgsqlException dbEx)
                    {
                        _logger.LogError(dbEx, "Database error: {ErrorMessage}", dbEx.Message);
                        return StatusCode(500, $"Database error: {dbEx.Message}");
                    }
                }

                _logger.LogInformation("Database operation successful. Triggering event...");
                
                // Trigger the user created event after successful DB operation
                _userService.CreateUser(userEvent);

                _logger.LogInformation("User {@UserEvent} successfully saved to database", userEvent);
                return Ok("User data saved successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Critical error: {ErrorType} - {ErrorMessage}", ex.GetType().Name, ex.Message);
                _logger.LogError("Stack Trace: {StackTrace}", ex.StackTrace);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }
}
