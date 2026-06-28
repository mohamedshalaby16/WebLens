using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebLens.Desktop.Models
{
    public class IntelligenceReport
    {
        public string PageType { get; set; } = "";
        public List<string> TechStack { get; set; } = new();
        public string Summary { get; set; } = "";
        public int ExternalLinks { get; set; }
        public int InternalLinks { get; set; }
    }
}