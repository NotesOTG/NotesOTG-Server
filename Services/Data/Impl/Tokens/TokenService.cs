using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using NotesOTG_Server.Models;
using NotesOTG_Server.Models.Contexts;

namespace NotesOTG_Server.Services.Data.Impl.Tokens
{
    public class TokenService: Service<RefreshToken>
    {
        public TokenService(DatabaseContext context, ILogger<TokenService> logger) : base(context, logger)
        {
        }

        public async Task<RefreshToken> FindByToken(string refreshToken)
        {
            return await entity.SingleOrDefaultAsync(e => e.Token == refreshToken);
        }

        public bool UpdateToken(RefreshToken refreshToken)
        {
            var updateToken = entity.Update(refreshToken);
            return updateToken != null;
        }

        public bool RemoveToken(RefreshToken refreshToken)
        {
            var tokenRemoval = entity.Remove(refreshToken);
            return tokenRemoval != null;
        }

        public async Task<bool> SaveChanges()
        {
            var save = await base.Save();
            return save;
        }

        public string GeneratePrimaryToken(string userId, string email)
        {
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@345"));
            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, userId),
                new Claim(ClaimTypes.Email, email)
            };
            var tokeOptions = new JwtSecurityToken(
                issuer: "https://localhost:44361",
                audience: "http://localhost:4200",
                /*                issuer: "http://notesotg.com/api",
                                audience: "https://notesotg.com",*/
                claims: claims,
                expires: DateTime.Now.AddMinutes(5),
                signingCredentials: signinCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(tokeOptions);
        }

        public async Task<string> IssueStandardRefresh(string token, string email)
        {
            var refreshToken = await FindByToken(token);
            if (refreshToken == null || !refreshToken.IsValid() || refreshToken.Email != email)
            {
                if (refreshToken != null)
                {
                    RemoveToken(refreshToken);
                    await SaveChanges();
                }
                return null;
            }
            
            refreshToken.Token = Guid.NewGuid().ToString();
            refreshToken.Provided = DateTime.Now;
            UpdateToken(refreshToken);
            await SaveChanges();
            return refreshToken.Token;
        }

        public async Task<string> IssueEmailRefresh(string email)
        {
            var refreshToken = new RefreshToken
            {
                Email = email,
                Token = Guid.NewGuid().ToString()
            };
            await entity.AddAsync(refreshToken);
            await SaveChanges();
            return refreshToken.Token;
        }
        
    }
}