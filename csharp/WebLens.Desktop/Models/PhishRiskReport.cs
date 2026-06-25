using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebLens.Desktop.Models
{
    public class PhishRiskReport
    {
        public int Score { get; set; }
        public string Verdict { get; set; } = "";
        public List<string> RedFlags { get; set; } = new();
        public string Explanation { get; set; } = "";
    }
}
