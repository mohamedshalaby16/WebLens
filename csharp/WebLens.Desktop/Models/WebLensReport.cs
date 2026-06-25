using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebLens.Desktop.Models
{
    public class WebLensReport
    {
        public string JobId { get; set; } = "";
        public string Url { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public string Status { get; set; } = "";
        public CloneInfo Clone { get; set; } = new();
        public IntelligenceReport Intelligence { get; set; } = new();
        public PhishRiskReport PhishingRisk { get; set; } = new();
    }
}
