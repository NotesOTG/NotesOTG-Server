using System;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using NotesOTG_Server.Models;
using NotesOTG_Server.Models.Http.Requests;
using NotesOTG_Server.Models.Http.Responses;
using NotesOTG_Server.Models.Http.Responses.impl;
using NotesOTG_Server.Services.Data.Impl.Email.Impl;
using NotesOTG_Server.Services.Data.Impl.Tokens;
using NotesOTG_Server.Services.Interfaces;

namespace NotesOTG_Server.Services
{
    public class UserService
    {

        private readonly UserManager<NotesUser> userManager;
        private readonly SignInManager<NotesUser> signInManager;
        private readonly RoleService roleService;
        private readonly TokenService tokenService;
        private readonly IConfiguration configuration;
        private readonly EmailTokenService emailTokenService;
        private readonly IHttpContextAccessor httpContext;
        
        public UserService ( UserManager<NotesUser> userManager,
            SignInManager<NotesUser> signInManager,
            RoleService roleService,
            TokenService tokenService,
            IConfiguration configuration,
            EmailTokenService emailTokenService,
            IHttpContextAccessor httpContext) 
        {
            this.userManager = userManager;
            this.roleService = roleService;
            this.tokenService = tokenService;
            this.signInManager = signInManager;
            this.configuration = configuration;
            this.emailTokenService = emailTokenService;
            this.httpContext = httpContext;
        }
        
        public async Task<LoginResponse> Login(LoginRequest request)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new LoginResponse {Success = false, Error = "Invalid email or password."};
            }

            var loginResult = await signInManager.CheckPasswordSignInAsync(user, request.Password, true);
            if (!loginResult.Succeeded)
            {
                return new LoginResponse {Success = false, Error = loginResult.IsLockedOut ? 
                    "This account is currently locked. Please check your email." 
                    : "Invalid email or password."};
            }
            
            var token = tokenService.GeneratePrimaryToken(user.Id, user.Email);
            var refreshToken = await tokenService.IssueEmailRefresh(user.Email);
            var roles = await roleService.GetUserRoles(user);
            var hasPassword = await userManager.HasPasswordAsync(user);
            var emailVerified = await userManager.IsEmailConfirmedAsync(user);
            return new LoginResponse {Success = true, Email = user.Email, Token = token, RefreshToken = refreshToken, Roles = roles, HasPassword = hasPassword, EmailVerified = emailVerified};
        }

        public async Task<RegisterResponse> Register(RegisterRequest request)
        {
            var notesUser = new NotesUser()
            {
                UserName = request.Email,
                Email = request.Email
            };

            var addUserTask = await userManager.CreateAsync(notesUser, request.Password);
            if (addUserTask.Succeeded)
            {
                await roleService.AddUserToRole(notesUser, RoleType.User);
                await emailTokenService.GenerateEmailVerificationToken(notesUser.Email);
                return new RegisterResponse {Success = true};
            }
            
            var errors = new StringBuilder();
            foreach (var error in addUserTask.Errors)
            {
                errors.Append(error.Description);
                errors.Append(":");
            }
            return new RegisterResponse { Success = false, Error = errors.ToString(0, errors.Length - 1)};
        }

        public async Task<LoginResponse> SocialLogin(SocialRequest socialRequest)
        {
            switch (socialRequest.SocialTypes)
            {
                case "Google":
                    return await GoogleLogin(socialRequest.IdToken);
                
                case "Facebook":
                    return await GoogleLogin(socialRequest.IdToken);
                
                case "Microsoft":
                    return await GoogleLogin(socialRequest.IdToken);
            }

            return null;
        }
        
        public async Task<LoginResponse> GoogleLogin(string googleToken)
        {
            GoogleJsonWebSignature.Payload payload;
            try
            {
                payload = await GoogleJsonWebSignature.ValidateAsync(googleToken,
                    new GoogleJsonWebSignature.ValidationSettings()
                    {
                        Audience = new[] {configuration.GetValue<string>("ExternalClientIds:Google")},
                        ForceGoogleCertRefresh = false,
                        //HostedDomain = "https://notesotg.com"
                    });
            }
            catch(InvalidJwtException e)
            {
                
                Console.WriteLine(e.ToString());
                return new LoginResponse {Success = false};
            }
            return await GetOrCreateExternalUser("Google", payload.Subject, payload.Email, payload.EmailVerified);
        }
        
        private async Task<LoginResponse> GetOrCreateExternalUser(string provider, string key, string email, bool emailConfirmed)
        {
            var user = await userManager.FindByLoginAsync(provider, key);
            if (user != null)
            {
                var token = tokenService.GeneratePrimaryToken(user.Id, user.Email);
                var refreshToken = await tokenService.IssueEmailRefresh(user.Email);
                var roles = await roleService.GetUserRoles(user);
                var hasPassword = await userManager.HasPasswordAsync(user);
                var emailVerified = await userManager.IsEmailConfirmedAsync(user);
                return new LoginResponse {Success = true, Email = user.Email, Token = token, RefreshToken = refreshToken, Roles = roles, HasPassword = hasPassword, EmailVerified = emailVerified };
            }
            Console.WriteLine("USer is: {0}" + user);

            user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new NotesUser
                {
                    Email = email,
                    UserName = email,
                    EmailConfirmed = emailConfirmed
                };
                await userManager.CreateAsync(user);
                await roleService.AddUserToRole(user, RoleType.User);
            }

            var info = new UserLoginInfo(provider, key, provider.ToUpperInvariant());
            var result = await userManager.AddLoginAsync(user, info);
            if (result.Succeeded)
            {
                var token = tokenService.GeneratePrimaryToken(user.Id, user.Email);
                var refreshToken = await tokenService.IssueEmailRefresh(user.Email);
                var roles = await roleService.GetUserRoles(user);
                var hasPassword = await userManager.HasPasswordAsync(user);
                var emailVerified = await userManager.IsEmailConfirmedAsync(user);
                return new LoginResponse {Success = true, Email = user.Email, Token = token, RefreshToken = refreshToken, Roles = roles, HasPassword = hasPassword, EmailVerified = emailVerified};
            }

            return new LoginResponse {Success = false};
        }

        public async Task<RefreshTokensResponse> RefreshTokens(RefreshTokenRequest request)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new RefreshTokensResponse { Success = false };
            }

            var refreshToken = await tokenService.IssueStandardRefresh(request.RefreshToken, request.Email);
            var token = tokenService.GeneratePrimaryToken(user.Id, user.Email);
            if (string.IsNullOrEmpty(refreshToken))
            {
                return new RefreshTokensResponse { Success = false };
            }
            return new RefreshTokensResponse { Success = true, PrimaryToken = token, RefreshToken = refreshToken };
        }
        
        public async Task<BasicResponse> EmailCheck(string email)
        {
            var emailExists = await userManager.FindByEmailAsync(email);
            return emailExists == null ? new BasicResponse{Success = true} 
                : new BasicResponse{Success = false, Error = "Email is already in use."};
        }

        public async Task<BasicResponse> UsernameCheck(string username)
        {
            var usernameExists = await userManager.FindByNameAsync(username);
            return usernameExists == null ? new BasicResponse{Success = true} 
                : new BasicResponse{Success = false, Error = "Username is already in use."};
        }

        public async Task<NotesUser> GetUser()
        {

            var email = httpContext.HttpContext.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email).Value;
            var user = await userManager.FindByEmailAsync(email);
            return user;
        }
        
    }
}