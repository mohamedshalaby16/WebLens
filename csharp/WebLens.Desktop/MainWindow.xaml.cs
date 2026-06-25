using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using WebLens.Desktop.Helpers;
using WebLens.Desktop.Models;
using WebLens.Desktop.Services;

namespace WebLens.Desktop
{
    public partial class MainWindow : Window
    {
        private readonly ApiClient _api;
        private WebLensReport? _currentReport;
        private string _currentJobId = "";

        public MainWindow()
        {
            InitializeComponent();
            _api = new ApiClient("http://localhost:8000");
            Loaded += MainWindow_Loaded;
        }

        // ── Startup ───────────────────────────────────────────────────────────

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await CheckServerStatusAsync();
        }

        private async Task CheckServerStatusAsync()
        {
            StatusBar.Text = "Checking server connection...";
            bool online = await _api.HealthCheckAsync();

            if (online)
            {
                StatusDot.Fill = new SolidColorBrush(Color.FromRgb(34, 197, 94));
                StatusText.Text = "Server Online";
                StatusBar.Text = "Ready — enter a URL to begin";
            }
            else
            {
                StatusDot.Fill = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                StatusText.Text = "Server Offline";
                StatusBar.Text = "Cannot connect to WebLens API — make sure Python server is running on port 8000";
                AnalyzeButton.IsEnabled = false;
            }
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            RefreshButton.IsEnabled = false;
            StatusText.Text = "Checking...";
            StatusDot.Fill = new SolidColorBrush(Color.FromRgb(234, 179, 8));
            await CheckServerStatusAsync();

            // Re-enable Analyze if server is back online
            bool online = StatusText.Text == "Server Online";
            AnalyzeButton.IsEnabled = online;
            RefreshButton.IsEnabled = true;
        }

        // ── Input ─────────────────────────────────────────────────────────────

        private void UrlInput_KeyDown(object sender,
            System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Enter)
                AnalyzeButton_Click(sender, e);
        }

        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            UrlInput.Text = "";
            UrlInput.Focus();
            ResultsPanel.Visibility = Visibility.Collapsed;
            LoadingPanel.Visibility = Visibility.Collapsed;
            EmptyState.Visibility = Visibility.Visible;
            _currentReport = null;
            _currentJobId = "";
            ExportPdfButton.IsEnabled = false;
            ViewCloneButton.IsEnabled = false;
            StatusBar.Text = "Ready — enter a URL to begin";
        }

        // ── Analysis ──────────────────────────────────────────────────────────

        private async void AnalyzeButton_Click(object sender, RoutedEventArgs e)
        {
            string url = UrlInput.Text.Trim();

            if (string.IsNullOrEmpty(url))
            {
                StatusBar.Text = "Please enter a URL";
                return;
            }

            if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                url = "https://" + url;

            await RunAnalysisAsync(url);
        }

        private async Task RunAnalysisAsync(string url)
        {
            // Set loading state
            EmptyState.Visibility = Visibility.Collapsed;
            ResultsPanel.Visibility = Visibility.Collapsed;
            LoadingPanel.Visibility = Visibility.Visible;
            LoadingText.Text = "Cloning page and downloading assets...";

            AnalyzeButton.IsEnabled = false;
            ClearButton.IsEnabled = false;
            ExportPdfButton.IsEnabled = false;
            ViewCloneButton.IsEnabled = false;

            try
            {
                // Step 1 — Clone
                StatusBar.Text = $"Cloning {url}...";
                LoadingText.Text = "Cloning page and downloading assets...";
                CloneResponse cloneResponse = await _api.CloneAsync(url);
                _currentJobId = cloneResponse.JobId;

                // Step 2 — Get Report
                StatusBar.Text = "Running AI analysis...";
                LoadingText.Text = "Analyzing page with AI plugins...";
                WebLensReport report = await _api.GetReportAsync(_currentJobId);
                _currentReport = report;

                // Step 3 — Display
                StatusBar.Text = $"Analysis complete — Risk Score: {report.PhishingRisk.Score}/100 ({report.PhishingRisk.Verdict})";
                DisplayReport(report);
            }
            catch (Exception ex)
            {
                LoadingPanel.Visibility = Visibility.Collapsed;
                EmptyState.Visibility = Visibility.Visible;
                StatusBar.Text = $"Error: {ex.Message}";
                MessageBox.Show(
                    $"Analysis failed:\n\n{ex.Message}",
                    "WebLens Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            finally
            {
                AnalyzeButton.IsEnabled = true;
                ClearButton.IsEnabled = true;
            }
        }

        // ── Display ───────────────────────────────────────────────────────────

        private void DisplayReport(WebLensReport report)
        {
            // Switch visibility — order matters
            LoadingPanel.Visibility = Visibility.Collapsed;
            EmptyState.Visibility = Visibility.Collapsed;
            ResultsPanel.Visibility = Visibility.Visible;

            string verdict = report.PhishingRisk.Verdict;
            Brush fg = RiskScoreHelper.GetScoreColor(verdict);
            Brush bg = RiskScoreHelper.GetScoreBackground(verdict);

            // Risk banner
            RiskBanner.Background = bg;
            RiskScoreText.Text = report.PhishingRisk.Score.ToString();
            RiskScoreText.Foreground = fg;
            RiskProgressBar.Value = report.PhishingRisk.Score;
            RiskProgressBar.Foreground = fg;

            var fgSolid = (SolidColorBrush)fg;
            VerdictBadge.Background = new SolidColorBrush(
                Color.FromArgb(40, fgSolid.Color.R, fgSolid.Color.G, fgSolid.Color.B));
            VerdictIcon.Text = RiskScoreHelper.GetVerdictIcon(verdict);
            VerdictIcon.Foreground = fg;
            VerdictText.Text = verdict.ToUpper();
            VerdictText.Foreground = fg;

            // Clone info
            PageTitleText.Text = string.IsNullOrEmpty(report.Clone.PageTitle)
                ? "—" : report.Clone.PageTitle;
            FetcherText.Text = report.Clone.FetcherUsed;
            AssetsText.Text = report.Clone.AssetsDownloaded.ToString();
            AssetsFailedText.Text = report.Clone.AssetsFailed.ToString();
            FormsText.Text = report.Clone.FormsFound.ToString();
            LinksText.Text = report.Clone.LinksFound.ToString();

            // Intelligence
            PageTypeText.Text = System.Globalization.CultureInfo.CurrentCulture
                .TextInfo.ToTitleCase(report.Intelligence.PageType);
            TechStackText.Text = report.Intelligence.TechStack.Count > 0
                ? string.Join(", ", report.Intelligence.TechStack)
                : "None detected";
            ExternalLinksText.Text = report.Intelligence.ExternalLinks.ToString();
            InternalLinksText.Text = report.Intelligence.InternalLinks.ToString();
            SummaryText.Text = report.Intelligence.Summary;

            // Red flags
            if (report.PhishingRisk.RedFlags.Count > 0)
            {
                RedFlagsCard.Visibility = Visibility.Visible;
                RedFlagsList.ItemsSource = report.PhishingRisk.RedFlags;
            }
            else
            {
                RedFlagsCard.Visibility = Visibility.Collapsed;
            }

            // Explanation
            ExplanationText.Text = report.PhishingRisk.Explanation;

            // Enable buttons
            ExportPdfButton.IsEnabled = true;
            ViewCloneButton.IsEnabled = true;
        }

        // ── Export PDF ────────────────────────────────────────────────────────

        private async void ExportPdfButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_currentJobId)) return;

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"weblens-report-{_currentJobId[..8]}",
                DefaultExt = ".pdf",
                Filter = "PDF files (*.pdf)|*.pdf"
            };

            if (dialog.ShowDialog() != true) return;

            try
            {
                StatusBar.Text = "Generating PDF...";
                ExportPdfButton.IsEnabled = false;

                byte[] pdfBytes = await _api.GetReportPdfAsync(_currentJobId);
                await File.WriteAllBytesAsync(dialog.FileName, pdfBytes);

                StatusBar.Text = $"PDF saved — {dialog.FileName}";

                var result = MessageBox.Show(
                    "PDF report saved successfully. Open it now?",
                    "Export Complete",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);

                if (result == MessageBoxResult.Yes)
                    Process.Start(new ProcessStartInfo(dialog.FileName)
                    { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                StatusBar.Text = $"PDF export failed: {ex.Message}";
                MessageBox.Show($"Failed to export PDF:\n\n{ex.Message}",
                    "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ExportPdfButton.IsEnabled = true;
            }
        }

        // ── View Clone ────────────────────────────────────────────────────────

        private void ViewCloneButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_currentJobId)) return;
            string url = $"http://localhost:8000/clone/{_currentJobId}";
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
    }
}