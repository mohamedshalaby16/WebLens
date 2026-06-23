using WebLens.Client.Models;

namespace WebLens.Client.Display;

public static class ReportPrinter
{
    public static void Print(WebLensReport report)
    {
        PrintDivider('=');
        Center("W E B L E N S   R E P O R T");
        PrintDivider('=');

        Console.WriteLine();
        Line("Job ID",    report.JobId);
        Line("URL",       report.Url);
        Line("Timestamp", report.Timestamp);
        Line("Status",    report.Status);

        // ── Clone ─────────────────────────────────────────────────────────────
        Console.WriteLine();
        Section("CLONE");
        Line("Fetcher used",       report.CloneInfo.FetcherUsed);
        Line("Page title",         string.IsNullOrEmpty(report.CloneInfo.PageTitle) ? "(none)" : report.CloneInfo.PageTitle);
        Line("Assets downloaded",  report.CloneInfo.AssetsDownloaded.ToString());
        Line("Assets failed",      report.CloneInfo.AssetsFailed.ToString());
        Line("Forms found",        report.CloneInfo.FormsFound.ToString());
        Line("Links found",        report.CloneInfo.LinksFound.ToString());

        // ── Intelligence ──────────────────────────────────────────────────────
        Console.WriteLine();
        Section("PAGE INTELLIGENCE");
        Line("Page type",  report.Intelligence.PageType);
        Line("Tech stack", report.Intelligence.TechStack.Count > 0
            ? string.Join(", ", report.Intelligence.TechStack)
            : "(none detected)");
        Line("External links", report.Intelligence.ExternalLinks.ToString());
        Line("Internal links", report.Intelligence.InternalLinks.ToString());
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine("  Summary:");
        Console.ResetColor();
        Console.WriteLine($"  {report.Intelligence.Summary}");

        if (report.Intelligence.Forms.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  Forms:");
            Console.ResetColor();
            foreach (var form in report.Intelligence.Forms)
            {
                Console.WriteLine($"    action={form.Action}  method={form.Method}");
                Console.WriteLine($"    fields: {string.Join(", ", form.Fields)}");
            }
        }

        // ── Phishing Risk ─────────────────────────────────────────────────────
        Console.WriteLine();
        Section("PHISHING RISK");

        Console.Write("  Score:   ");
        PrintColoredScore(report.PhishingRisk.Score);
        Console.WriteLine();

        Console.Write("  Verdict: ");
        PrintColoredVerdict(report.PhishingRisk.Verdict);
        Console.WriteLine();

        if (report.PhishingRisk.RedFlags.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  Red Flags:");
            Console.ResetColor();
            foreach (var flag in report.PhishingRisk.RedFlags)
                Console.WriteLine($"    ! {flag}");
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine("  Explanation:");
        Console.ResetColor();
        Console.WriteLine($"  {report.PhishingRisk.Explanation}");

        Console.WriteLine();
        PrintDivider('=');
        Console.WriteLine();
    }

    public static void PrintJobList(List<JobStatus> jobs)
    {
        if (jobs.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("No jobs found.");
            Console.ResetColor();
            return;
        }

        PrintDivider('-');
        Console.WriteLine($"  {"JOB ID",-38} {"STATUS",-12} {"VERDICT",-10} {"SCORE",-6} URL");
        PrintDivider('-');

        foreach (var job in jobs)
        {
            Console.Write($"  {job.JobId,-38} ");
            PrintColoredStatus(job.Status);
            Console.Write($" {(job.Verdict ?? "-"),-10} {(job.RiskScore?.ToString() ?? "-"),-6} {job.Url}");
            Console.WriteLine();
        }

        PrintDivider('-');
        Console.WriteLine($"  {jobs.Count} job(s) total");
        Console.WriteLine();
    }

    public static void PrintError(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Error: {message}");
        Console.ResetColor();
    }

    public static void PrintSuccess(string message)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(message);
        Console.ResetColor();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void PrintColoredScore(int score)
    {
        Console.ForegroundColor = score switch
        {
            <= 20 => ConsoleColor.Green,
            <= 40 => ConsoleColor.Cyan,
            <= 60 => ConsoleColor.Yellow,
            <= 80 => ConsoleColor.Red,
            _     => ConsoleColor.DarkRed,
        };
        Console.Write($"{score}/100");
        Console.ResetColor();
    }

    private static void PrintColoredVerdict(string verdict)
    {
        Console.ForegroundColor = verdict switch
        {
            "Safe"     => ConsoleColor.Green,
            "Low"      => ConsoleColor.Cyan,
            "Moderate" => ConsoleColor.Yellow,
            "High"     => ConsoleColor.Red,
            "Critical" => ConsoleColor.DarkRed,
            _          => ConsoleColor.Gray,
        };
        Console.Write(verdict);
        Console.ResetColor();
    }

    private static void PrintColoredStatus(string status)
    {
        Console.ForegroundColor = status switch
        {
            "completed" => ConsoleColor.Green,
            "running"   => ConsoleColor.Cyan,
            "pending"   => ConsoleColor.Yellow,
            "failed"    => ConsoleColor.Red,
            _           => ConsoleColor.Gray,
        };
        Console.Write($"{status,-12}");
        Console.ResetColor();
    }

    private static void Section(string title)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  ── {title} ──");
        Console.ResetColor();
    }

    private static void Line(string label, string value)
    {
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write($"  {label,-20} ");
        Console.ResetColor();
        Console.WriteLine(value);
    }

    private static void PrintDivider(char ch) =>
        Console.WriteLine(new string(ch, 70));

    private static void Center(string text)
    {
        int padding = (70 - text.Length) / 2;
        Console.WriteLine(text.PadLeft(padding + text.Length));
    }
}
