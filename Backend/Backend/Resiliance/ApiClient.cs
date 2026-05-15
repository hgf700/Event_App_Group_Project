//using Microsoft.Extensions.FileSystemGlobbing.Internal;
//using Twilio.Jwt.Taskrouter;
//using Twilio.Types;

//namespace Backend.Resiliance;

//public class ApiClient
//{
//    private readonly HttpClient _httpClient;

//    public ApiClient(HttpClient httpClient)
//    {
//        _httpClient = httpClient;
//    }

//    public async Task<T?> GetAsync<T>(string url)
//    {
//        return await _httpClient.GetFromJsonAsync<T>(url);
//    }

//    //public async Task<T?> GetAsync<T>(int id)
//    //{
//    //    return await _httpClient.GetFromJsonAsync<T>($"{id}");
//    //}

//    //public async Task<T?> GetAsync<T>(string endpoint, int id)
//    //{
//    //    return await _httpClient.GetFromJsonAsync<T>($"{endpoint}/{id}");
//    //}

//    //var user = await apiClient.GetAsync<UserDto>("users", 1);
//}


//// .AddStandardResilienceHandler() = retry, timeout, circuit breaker, rate limiter, attempt timeout
//using Microsoft.Extensions.Http.Resilience;
//using Polly;

//builder.Services.AddHttpClient<ApiClient>(client =>
//{
//    client.BaseAddress = new Uri("https://localhost:7051");
//    client.Timeout = TimeSpan.FromSeconds(12);
//})
//.AddResilienceHandler("MyResilianceHandler", builder =>
//{
//    builder.AddRetry(new HttpRetryStrategyOptions
//    {
//        MaxRetryAttempts = 3,
//        Delay = TimeSpan.FromSeconds(2),
//        BackoffType = DelayBackoffType.Exponential,
//        UseJitter = true
//    });

//    builder.AddTimeout(TimeSpan.FromSeconds(5));

//    builder.AddCircuitBreaker(new HttpCircuitBreakerStrategyOptions
//    {
//        SamplingDuration = TimeSpan.FromSeconds(30),
//        FailureRatio = 0.3,
//        MinimumThroughput = 20
//    });
//});
