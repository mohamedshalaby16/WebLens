using WebLens.Client;
using WebLens.Client.Display;

const string ApiBase = "http://localhost:8000";

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

using var api = new ApiClient(ApiBase);

// Verify API is reachable before doing anything
if (!await api.HealthCheckAsync())
{
    ReportPrinter.PrintError($"Cannot reach WebLens API at {ApiBase}. Is it running?");
    return 1;
}

return args[0] switch
{
    "scan"  => await RunScan(api, args),
    "jobs"  => await RunJobs(api),
    "report" => await RunReport(api, args),
    _ => InvalidCommand(args[0]),
};

// ── Commands ──────────────────────────────────────────────────────────────────

static async Task<int> RunScan(ApiClient api, string[] args)
{
    if (args.Length < 2)
    {
        ReportPrinter.PrintError("Usage: weblens scan <url> [fetcher]");
        return 1;
    }

    string url = args[1];
    string? forceFetcher = args.Length >= 3 ? args[2] : null;

    Console.WriteLine($"Scanning: {url}");
    if (forceFetcher is not null)
        Console.WriteLine($"Fetcher:  {forceFetcher}");
    Console.WriteLine();

    try
    {
        var cloneResponse = await api.PostCloneAsync(url, forceFetcher);
        ReportPrinter.PrintSuccess($"Job completed: {cloneResponse.JobId}");
        Console.WriteLine();

        var report = await api.GetReportAsync(cloneResponse.JobId);
        ReportPrinter.Print(report);
        return 0;
    }
    catch (HttpRequestException ex)
    {
        ReportPrinter.PrintError($"Request failed: {ex.Message}");
        return 1;
    }
    catch (Exception ex)
    {
        ReportPrinter.PrintError(ex.Message);
        return 1;
    }
}

static async Task<int> RunJobs(ApiClient api)
{
    try
    {
        var jobs = await api.GetJobsAsync();
        ReportPrinter.PrintJobList(jobs);
        return 0;
    }
    catch (Exception ex)
    {
        ReportPrinter.PrintError(ex.Message);
        return 1;
    }
}

static async Task<int> RunReport(ApiClient api, string[] args)
{
    if (args.Length < 2)
    {
        ReportPrinter.PrintError("Usage: weblens report <job-id>");
        return 1;
    }

    try
    {
        var report = await api.GetReportAsync(args[1]);
        ReportPrinter.Print(report);
        return 0;
    }
    catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
    {
        ReportPrinter.PrintError($"No report found for job ID: {args[1]}");
        return 1;
    }
    catch (Exception ex)
    {
        ReportPrinter.PrintError(ex.Message);
        return 1;
    }
}

static int InvalidCommand(string cmd)
{
    ReportPrinter.PrintError($"Unknown command: {cmd}");
    PrintUsage();
    return 1;
}

static void PrintUsage()
{
    Console.WriteLine("WebLens Client");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  weblens scan <url> [fetcher]   Scan a URL and print the full report");
    Console.WriteLine("  weblens jobs                   List all past jobs");
    Console.WriteLine("  weblens report <job-id>        Fetch and print a saved report");
    Console.WriteLine();
    Console.WriteLine("Fetcher options: Fetcher | DynamicFetcher | StealthyFetcher");
}
