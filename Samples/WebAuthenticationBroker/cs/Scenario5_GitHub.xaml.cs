using Newtonsoft.Json;
using SDKTemplate;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace WebAuthentication
{
    // Thanks to https://gist.github.com/technoweenie/419219
    // Further reading on secrets https://stackoverflow.com/q/4419915/1542187

    public sealed partial class Scenario5_GitHub : Page
    {
        private MainPage rootPage = MainPage.Current;
        bool authzInProgress = false;

        public Scenario5_GitHub()
        {
            this.InitializeComponent();
        }

        private async void Launch_Click(object sender, RoutedEventArgs e)
        {
            if (authzInProgress)
            {
                return;
            }

            returnedTokenBlock.Text = "";
            gitHubUserNameBlock.Text = "";

            if (String.IsNullOrEmpty(appClientIdBox.Text))
            {
                rootPage.NotifyUser("Please enter a Client ID.", NotifyType.StatusMessage);
                return;
            }

            var callback = "https://github.com/login/oauth/success";
            var callbackUri = new Uri(callback);

            Guid state = Guid.NewGuid();

            var startUri = $"github.com/login/oauth/authorize?scope=user:email&client_id={Uri.EscapeDataString(appClientIdBox.Text)}&display=popup&type=user_agent&redirect_uri={Uri.EscapeDataString(callbackUri.AbsoluteUri)}&state={state}";
            Uri gitHubStartUri = new Uri($"https://{startUri}");

            rootPage.NotifyUser($"Navigating to {gitHubStartUri}", NotifyType.StatusMessage);

            authzInProgress = true;
            try
            {
                WebAuthenticationResult WebAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, gitHubStartUri, callbackUri);
                if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
                {
                    returnedTokenBlock.Text = WebAuthenticationResult.ResponseData;
                    await GetGitHubUserNameAsync(WebAuthenticationResult.ResponseData, state, appClientIdBox.Text);
                }
                else if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.ErrorHttp)
                {
                    returnedTokenBlock.Text = $"HTTP error: {WebAuthenticationResult.ResponseErrorDetail}";
                }
                else
                {
                    returnedTokenBlock.Text = $"Error: {WebAuthenticationResult.ResponseStatus}";
                }

            }
            catch (Exception Error)
            {
                rootPage.NotifyUser(Error.Message, NotifyType.ErrorMessage);
            }

            authzInProgress = false;
        }

        private async Task GetGitHubUserNameAsync(string responseData, Guid state, string clientId)
        {
            var url = new Uri(responseData);

            var queryStringDictionary = GetParams(url.Query);
            
            string code = queryStringDictionary["code"];
            Guid recievedState = Guid.Parse(queryStringDictionary["state"]);

            if (recievedState != state)
            {
                throw new Exception("Woops");
            }

            HttpClient httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            var request = new Request
            {
                client_id = clientId,
                client_secret = appClientSecretBox.Password,
                code = code,
                state = state.ToString()
            };
            var content = new StringContent(JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");

            var what = await httpClient.PostAsync(new Uri("https://github.com/login/oauth/access_token"), content);

            var res = await what.Content.ReadAsStringAsync();

            var resObj = JsonConvert.DeserializeObject<Response>(res);

            var access_token = resObj.Access_Token;

            await GetUserName(access_token);
        }

        private async Task GetUserName(string access_token)
        {
            Uri uri = new Uri("https://api.github.com/user");

            var httpClient = new HttpClient();
            https://stackoverflow.com/questions/22649419/protocol-violation-using-github-api
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("token", access_token);
            httpClient.DefaultRequestHeaders.Add("User-Agent", appClientNameBox.Text);

            try
            {
                var response = await httpClient.GetAsync(uri);

                dynamic what = JsonConvert.DeserializeObject(await response.Content.ReadAsStringAsync());
                
                gitHubUserNameBlock.Text = what.login;
            }
            catch (Exception)
            {
                gitHubUserNameBlock.Text = "Error contacting GitHub";
            }
        }

        //https://codereview.stackexchange.com/questions/1588/get-params-from-a-url
        static IDictionary<string, string> GetParams(string uri)
        {
            var matches = Regex.Matches(uri, @"[\?&](([^&=]+)=([^&=#]*))", RegexOptions.Compiled);
            return matches.Cast<Match>().ToDictionary(
                m => Uri.UnescapeDataString(m.Groups[2].Value),
                m => Uri.UnescapeDataString(m.Groups[3].Value)
            );
        }

        private class Request
        {
            public string client_id { get; set; }
            public string client_secret { get; set; }
            public string code { get; set; }
            public string state { get; set; }
        }

        private class Response
        {
            public string Access_Token { get; set; }
            public string Scope { get; set; }
            public string Token_Type { get; set; }
        }
    }
}
