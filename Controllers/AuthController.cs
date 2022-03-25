using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NotesOTG_Server.Models.Http.Requests;
using NotesOTG_Server.Models.Http.Responses;
using NotesOTG_Server.Services;
using NotesOTG_Server.Services.Data.Impl.Tokens;
using NotesOTG_Server.Services.Interfaces;

namespace NotesOTG_Server.Controllers
{
    
    public class AuthController : BaseController
    {
        
        private readonly UserService userService;
        private readonly TokenService tokenService;

        public AuthController(UserService userService, TokenService tokenService)
        {
            this.userService = userService;
            this.tokenService = tokenService;
        }
        
        [HttpPost("Register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterRequest request)
        {
            return Ok(await userService.Register(request));
        }
        
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            return Ok(await userService.Login(request));
        }

        [HttpPost("refreshTokens")]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshTokens(RefreshTokenRequest request)
        {
            var tokenRefresh = await userService.RefreshTokens(request);
            return tokenRefresh.Success ? (IActionResult) Ok(tokenRefresh) : Unauthorized();
        }
        
        [HttpGet("checkEmail")]
        [AllowAnonymous]
        public async Task<IActionResult> CheckEmail(string email)
        {
            return Ok(await userService.EmailCheck(email));
        }

        [HttpGet("checkUsername")]
        [AllowAnonymous]
        public async Task<IActionResult> CheckUsername([Required]string username)
        {
            return Ok(await userService.UsernameCheck(username));
        }

        [HttpPost("socialLogin")]
        public async Task<IActionResult> SocialLogin(SocialRequest socialRequest)
        {
            return Ok(await userService.SocialLogin(socialRequest));
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<BasicResponse> Logout(string refreshToken)
        {
            if (!string.IsNullOrWhiteSpace(refreshToken))
            {
                var tokenSearch = await tokenService.FindByToken(refreshToken);
                if (tokenSearch != null)
                {
                    tokenService.RemoveToken(tokenSearch);
                    await tokenService.SaveChanges();
                    return new BasicResponse { Success = true };
                }
            }

            return new BasicResponse { Success = false };
        }


    }
}