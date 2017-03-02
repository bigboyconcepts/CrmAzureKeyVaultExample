using Microsoft.Xrm.Sdk;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization.Json;
using System.Threading.Tasks;

namespace CrmAzureKeyVaultExample
{
    public class RetrieveAzureSecret : IPlugin
    {
        public void Execute(IServiceProvider serviceProvider)
        {
            IPluginExecutionContext context =
                (IPluginExecutionContext)serviceProvider.GetService(typeof(IPluginExecutionContext));

            //Assume these values came from secure configuration
            string clientId = "00000000-0000-0000-0000-000000000000";
            string clientSecret = "00000000000000000000000000000000000000000000";
            string tenantId = "00000000-0000-0000-0000-000000000000";
            //Name your secret so it contains your CRM Org.Name and then do a replace, this way
            //you can mange values from Azure and not change code or configuration in CRM
            string secretUrl =
                "https://vaultname.vault.azure.net/secrets/**orgname**SecretName/00000000000000000000000000000000";
            secretUrl = secretUrl.Replace("**orgname**", context.OrganizationName);

            var getTokenTask = Task.Run(async () => await GetToken(clientId, clientSecret, tenantId));
            Task.WaitAll(getTokenTask);

            if (getTokenTask.Result == null)
                throw new InvalidPluginExecutionException("Error retriving access token");

            //Deserial the token response to get the access token
            TokenResponse tokenResponse = DeserializeResponse<TokenResponse>(getTokenTask.Result);
            string token = tokenResponse.access_token;
            var getKeyTask = Task.Run(async () => await GetSecret(token, secretUrl));
            Task.WaitAll(getKeyTask);

            if (getKeyTask.Result == null)
                throw new InvalidPluginExecutionException("Error retriving secret from key vault");

            //Deserialize the vault response to get the secret
            VaultResponse vaultResponse = DeserializeResponse<VaultResponse>(getKeyTask.Result);
            //returnedValue is the Azure Key Vault Secret
            string returnedValue = vaultResponse.value;
        }

        private T DeserializeResponse<T>(string response)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
                StreamWriter writer = new StreamWriter(stream);
                writer.Write(response);
                writer.Flush();
                stream.Position = 0;
                T responseObject = (T)serializer.ReadObject(stream);
                return responseObject;
            }
        }

        private async Task<string> GetToken(string clientId, string clientSecret, string tenantId)
        {
            using (HttpClient httpClient = new HttpClient())
            {
                var formContent = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("resource", "https://vault.azure.net"),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("grant_type", "client_credentials")
                });

                HttpResponseMessage response = await httpClient.PostAsync(
                    "https://login.windows.net/" + tenantId + "/oauth2/token", formContent);

                return !response.IsSuccessStatusCode ? null
                    : response.Content.ReadAsStringAsync().Result;
            }
        }

        private async Task<string> GetSecret(string token, string secretUrl)
        {
            using (HttpClient httpClient = new HttpClient())
            {
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get,
                        new Uri(secretUrl + "?api-version=2016-10-01"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                HttpResponseMessage response = await httpClient.SendAsync(request);

                return !response.IsSuccessStatusCode ? null
                    : response.Content.ReadAsStringAsync().Result;
            }
        }
    }
}
