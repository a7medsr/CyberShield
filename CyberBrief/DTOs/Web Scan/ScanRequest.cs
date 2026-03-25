using System.ComponentModel.DataAnnotations;

namespace CyberBrief.DTOs.Web_Scan
{
    public class WebScanRequest
    {
        [Required]
        public string Target { get; set; } = string.Empty;
    }
}
