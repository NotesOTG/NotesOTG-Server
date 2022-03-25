using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NotesOTG_Server.Models;
using NotesOTG_Server.Models.Contexts;
using NotesOTG_Server.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using NotesOTG_Server.Services.Data.Impl.Tokens;
using NotesOTG_Server.Services.Data.Impl;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;

namespace NotesOTG_Server
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            string connectionString = "testing";
            services.AddDbContext<DatabaseContext>(options =>
            {
                options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
            });

            services.AddCors(o => o.AddPolicy("CorsPolicy", builder =>
            {
                builder
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowAnyOrigin();
            }));

            services.AddIdentity<NotesUser, IdentityRole>(options =>
                {
                    options.Password = new PasswordOptions
                    {
                        RequiredLength = 8,
                        RequireUppercase = true,
                        RequireDigit = true,
                        RequiredUniqueChars = 1,
                        RequireLowercase = true,
                        RequireNonAlphanumeric = true
                    };
                    options.User.RequireUniqueEmail = true;
                    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                    options.SignIn.RequireConfirmedAccount = false;
                    options.Password.RequiredUniqueChars = 1;
                    options.Password.RequireDigit = true;
                    options.Password.RequiredLength = 8;
                    options.Password.RequireUppercase = true;
                    options.Password.RequireLowercase = true;
                    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
                })
                .AddEntityFrameworkStores<DatabaseContext>()
                .AddDefaultTokenProviders();

                services.AddAuthentication(opt => {
                    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })

               .AddJwtBearer(options =>
               {
                   options.TokenValidationParameters = new TokenValidationParameters
                   {
                       ValidateIssuer = true,
                       ValidateAudience = true,
                       ValidateLifetime = true,
                       ValidateIssuerSigningKey = true,
                       RequireExpirationTime = true,
                       ClockSkew = TimeSpan.Zero,//add five minute grace period by default

                       ValidIssuer = "https://localhost:44361",
                       ValidAudience = "http://localhost:4200",
                       /*                       ValidIssuer = "http://notesotg.com/api",
                                              ValidAudience = "https://notesotg.com",*/
                       IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@345"))
                   };
               });

            services.AddHttpContextAccessor();
            services.AddTransient(typeof(RoleService));
            services.AddTransient(typeof(UserService));
            services.AddTransient(typeof(EmailTokenService));
            services.AddTransient(typeof(TokenService));
            services.AddTransient(typeof(NotesService));

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            });

            app.UseCors(config => config.AllowAnyHeader().AllowAnyMethod().WithOrigins("https://notesotg.com", "http://localhost:4200").AllowCredentials());
            //app.UseCors(config => config.AllowAnyHeader().AllowAnyMethod().WithOrigins("https://notesotg.com", "https://www.notesotg.com").AllowCredentials());
            
            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();
            
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
