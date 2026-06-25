using System.Windows.Media;

namespace WebLens.Desktop.Helpers
{
    public static class RiskScoreHelper
    {
        public static Brush GetScoreColor(string verdict) => verdict switch
        {
            "Safe" => new SolidColorBrush(Color.FromRgb(22, 163, 74)),
            "Low" => new SolidColorBrush(Color.FromRgb(13, 148, 136)),
            "Moderate" => new SolidColorBrush(Color.FromRgb(180, 83, 9)),
            "High" => new SolidColorBrush(Color.FromRgb(185, 28, 28)),
            "Critical" => new SolidColorBrush(Color.FromRgb(127, 29, 29)),
            _ => new SolidColorBrush(Color.FromRgb(30, 58, 138)),
        };

        public static Brush GetScoreBackground(string verdict) => verdict switch
        {
            "Safe" => new SolidColorBrush(Color.FromRgb(240, 253, 244)),
            "Low" => new SolidColorBrush(Color.FromRgb(240, 253, 250)),
            "Moderate" => new SolidColorBrush(Color.FromRgb(255, 247, 237)),
            "High" => new SolidColorBrush(Color.FromRgb(254, 242, 242)),
            "Critical" => new SolidColorBrush(Color.FromRgb(254, 242, 242)),
            _ => new SolidColorBrush(Color.FromRgb(219, 234, 254)),
        };

        public static string GetVerdictIcon(string verdict) => verdict switch
        {
            "Safe" => "✓",
            "Low" => "⚠",
            "Moderate" => "⚠",
            "High" => "✗",
            "Critical" => "✗",
            _ => "?",
        };
    }
}