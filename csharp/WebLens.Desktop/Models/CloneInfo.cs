using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebLens.Desktop.Models
{
    public class CloneInfo
    {
        public string FetcherUsed { get; set; } = "";
        public int AssetsDownloaded { get; set; }
        public int AssetsFailed { get; set; }
        public int FormsFound { get; set; }
        public int LinksFound { get; set; }
        public string ClonePath { get; set; } = "";
        public string PageTitle { get; set; } = "";
    }
}
