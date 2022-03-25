using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Google.Apis.Auth.OAuth2;
using MimeKit;
using Newtonsoft.Json.Linq;
using MailKit.Net.Smtp;
using MailKit.Security;

namespace NotesOTG_Server.Services.Background
{
    public class TimedEmailService : IHostedService, IDisposable
    {
        
        private readonly IHostApplicationLifetime applicationLifetime;
        private readonly ILogger<TimedEmailService> logger;
        private Timer timer;

        private ServiceAccountCredential credential;
        private readonly SmtpClient smtpClient = new SmtpClient();
        private readonly Dictionary<string, ServiceCredential> credentialsList = new Dictionary<string, ServiceCredential>();

        public static readonly List<MimeMessage> PendingEmails = new List<MimeMessage>();

        public TimedEmailService(ILogger<TimedEmailService> logger, IHostApplicationLifetime applicationLifetime)
        {
            this.logger = logger;
            this.applicationLifetime = applicationLifetime;
        }

        public void Dispose()
        {
            timer?.Dispose();
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            //logger.LogInformation("Timed Email Service Running");
            var validCredentials = await GetCredential("support@notesotg.com");
            if (!validCredentials)
            {
                logger.LogCritical("Failed to get valid email Credentials!");
                applicationLifetime.StopApplication();
            }
            timer = new Timer(SendAllEmails, null, TimeSpan.Zero, TimeSpan.FromMinutes(1));
        }

        private async void SendAllEmails(object state)
        {
            if (PendingEmails.Count < 1)
            {
                //logger.LogInformation("Email list bag is empty");
                return;
            }
            
            if (!smtpClient.IsConnected)
            {
                //logger.LogInformation("We have to get connected again!");
                await smtpClient.ConnectAsync("smtp.gmail.com", 465, SecureSocketOptions.SslOnConnect);
            }

            foreach (var pendingEmail in PendingEmails)
            {
                //SaslMechanismOAuth2 oauth2 = new SaslMechanismOAuth2("support@notesotg.com", CredentialsList["support@notesotg.com"].Token.AccessToken);
                SaslMechanismOAuth2 oauth2 = new SaslMechanismOAuth2(pendingEmail.From.ToString(), credentialsList[pendingEmail.From.ToString()].Token.AccessToken);
                if (!smtpClient.IsAuthenticated)
                {
                    await smtpClient.AuthenticateAsync(oauth2);   
                }
                await smtpClient.SendAsync(pendingEmail);
                //logger.LogInformation("Emails have been sent!");
            }
            PendingEmails.Clear();
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            //logger.LogInformation("Time Email Service is stopping");
            timer?.Change(Timeout.Infinite, 0);
            return Task.CompletedTask;
        }
        
        private async Task<bool> GetCredential(string email)
        {
            var file = await File.ReadAllTextAsync("./Data/skilful-sensor-345209-53d456e1f7e0.json");
            //var file = await File.ReadAllTextAsync("C:/Users/wante/Desktop/vivid-bond-307003-2041f21c86a4.json");
            var jsonObject = JObject.Parse(file);

            credential = new ServiceAccountCredential(new ServiceAccountCredential
                .Initializer("admin-282@skilful-sensor-345209.iam.gserviceaccount.com")
                {
                    // Note: other scopes can be found here: https://developers.google.com/gmail/api/auth/scopes
                    Scopes = new[] { "https://mail.google.com/" },
                    User = email
                }.FromPrivateKey(jsonObject.SelectToken("private_key")?.ToString()));

            var result = await credential.RequestAccessTokenAsync(CancellationToken.None);
            if (result)
            {
                credentialsList.Add(email, credential);
            }
            return result;
        }
    }
}
