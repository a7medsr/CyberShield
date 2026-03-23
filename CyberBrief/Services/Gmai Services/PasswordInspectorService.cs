using CyberBrief.Context;
using CyberBrief.Dtos.Gmail;
using CyberBrief.Models.PassordCheaking;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;


public class PasswordInspectorService
{
    private readonly HttpClient _http;
    private readonly CyberBriefDbContext _context;
    // guesses per second used to estimate crack time (tune as needed)
    private readonly double _guessesPerSecond = 1e10; // 10 billion (fast GPU rig)

    public PasswordInspectorService(HttpClient http,CyberBriefDbContext context)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _context = context;
    }

    /// <summary>
    /// Main entry: analyze password and return a user-friendly report.
    /// </summary>
    public async Task<PasswordReportDto> InspectAsync(string password)
    {
        // 1. Generate Hash for DB Lookup (Privacy First!)
        string pwdHash = GenerateSha1(password);

        // 2. Check Cache
        var cached = await _context.PasswordAudits
            .FirstOrDefaultAsync(x => x.PasswordHash == pwdHash);

        // Check if cache is fresh (e.g., less than 30 days old)
        if (cached != null && cached.CheckedAt > DateTime.UtcNow.AddDays(-30))
        {
            return MapToDto(password, cached);
        }

        // 3. Logic for New/Expired Audit
        var entropy = EstimateEntropyBits(password, out _);
        var score = MapEntropyToScore(entropy);
        var crackSeconds = EstimateCrackTimeSeconds(entropy, _guessesPerSecond);
        var crackDisplay = HumanReadableTime(crackSeconds);

        int pwnedCount = await GetPwnedCountAsync(password);

        // 4. Update or Add to Database
        if (cached == null)
        {
            _context.PasswordAudits.Add(new PasswordAudit
            {
                PasswordHash = pwdHash,
                PwnedCount = pwnedCount,
                Entropy = entropy,
                Score = score,
                CrackTimeDisplay = crackDisplay
            });
        }
        else
        {
            cached.PwnedCount = pwnedCount;
            cached.CheckedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();

        return MapToDto(password, new PasswordAudit
        {
            PwnedCount = pwnedCount,
            Entropy = entropy,
            Score = score,
            CrackTimeDisplay = crackDisplay
        });
    }

    // Helper to keep code clean
    private string GenerateSha1(string input)
    {
        using var sha1 = SHA1.Create();
        var hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(hashBytes).Replace("-", "").ToUpperInvariant();
    }

    private PasswordReportDto MapToDto(string rawPassword, PasswordAudit audit)
    {
        return new PasswordReportDto
        {
            MaskedPassword = Mask(rawPassword),
            Score = audit.Score,
            ScoreText = $"{audit.Score}/4",
            EntropyBits = Math.Round(audit.Entropy, 2),
            CrackTimeDisplay = audit.CrackTimeDisplay,
            PwnedCount = audit.PwnedCount,
            IsPwned = audit.PwnedCount > 0,
            Summary = audit.PwnedCount > 0
                ? $"Seen {audit.PwnedCount} times in breaches."
                : "Not found in known breach datasets."
        };
    }


    // ----------------- Helpers -----------------

    private double EstimateEntropyBits(string password, out int charsetSize)
    {
        bool hasLower = Regex.IsMatch(password, "[a-z]");
        bool hasUpper = Regex.IsMatch(password, "[A-Z]");
        bool hasDigits = Regex.IsMatch(password, "[0-9]");
        bool hasSymbols = Regex.IsMatch(password, @"[^\w\s]");
        bool hasSpace = password.Contains(' ');
        bool hasOther = password.Any(c => c > 127); // non-ascii

        int size = 0;
        if (hasLower) size += 26;
        if (hasUpper) size += 26;
        if (hasDigits) size += 10;
        if (hasSymbols) size += 32; // approximate
        if (hasSpace) size += 1;
        if (hasOther) size += 100; // rough boost for unicode

        if (size == 0) size = 26; // fallback

        double bitsPerChar = Math.Log(size, 2);
        double entropy = password.Length * bitsPerChar;

        // penalties for weak patterns
        if (IsMostlyRepeated(password)) entropy *= 0.6;
        if (ContainsCommonPasswordFragment(password)) entropy *= 0.8;

        charsetSize = size;
        return entropy;
    }

    private bool IsMostlyRepeated(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        var groups = s.GroupBy(c => c).Select(g => g.Count()).OrderByDescending(i => i).ToArray();
        return groups.Length > 0 && groups[0] >= Math.Max(2, s.Length * 0.6);
    }

    private static readonly string[] _commonFragments = new[]
    {
            "password","1234","qwerty","admin","letmein","welcome","iloveyou","abc123","0000","pass"
        };

    private bool ContainsCommonPasswordFragment(string s)
    {
        var lower = s.ToLowerInvariant();
        return _commonFragments.Any(f => lower.Contains(f));
    }

    private int MapEntropyToScore(double entropy)
    {
        if (entropy < 28) return 0;
        if (entropy < 36) return 1;
        if (entropy < 60) return 2;
        if (entropy < 80) return 3;
        return 4;
    }

    private double EstimateCrackTimeSeconds(double entropyBits, double guessesPerSecond)
    {
        if (double.IsNaN(entropyBits) || entropyBits <= 0) return 0;

        const double ENTROPY_THRESHOLD = 1024.0;
        if (entropyBits > ENTROPY_THRESHOLD) return double.MaxValue;

        double exponent = entropyBits - 1.0;
        double guesses = Math.Pow(2.0, exponent);

        if (double.IsInfinity(guesses) || double.IsNaN(guesses)) return double.MaxValue;

        double seconds = guesses / Math.Max(1.0, guessesPerSecond);

        if (double.IsInfinity(seconds) || double.IsNaN(seconds) || seconds > 1e308) return double.MaxValue;
        return seconds;
    }

    private string HumanReadableTime(double seconds)
    {
        if (seconds <= 1) return "less than a second";
        if (seconds < 60) return $"{Math.Round(seconds, 1)} seconds";
        if (seconds < 3600) return $"{Math.Round(seconds / 60.0, 1)} minutes";
        if (seconds < 86400) return $"{Math.Round(seconds / 3600.0, 1)} hours";
        if (seconds < 31536000) return $"{Math.Round(seconds / 86400.0, 1)} days";
        // use long literal to avoid compile-time overflow
        if (seconds < 31536000L * 100) return $"{Math.Round(seconds / 31536000.0, 1)} years";
        return "centuries";
    }

    private string Mask(string password)
    {
        if (string.IsNullOrEmpty(password)) return "";
        if (password.Length <= 2) return new string('*', password.Length);
        var shown = password.Substring(0, Math.Min(2, password.Length));
        return shown + new string('*', Math.Max(3, password.Length - shown.Length));
    }

    /// <summary>
    /// HIBP k-anonymity check. Returns times seen (0 if not found).
    /// </summary>
    public async Task<int> GetPwnedCountAsync(string password)
    {
        // SHA1 uppercase hex
        using var sha1 = SHA1.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hashBytes = sha1.ComputeHash(bytes);
        var hash = BitConverter.ToString(hashBytes).Replace("-", "").ToUpperInvariant();

        var prefix = hash.Substring(0, 5);
        var suffix = hash.Substring(5);

        var url = $"https://api.pwnedpasswords.com/range/{prefix}";
        using var resp = await _http.GetAsync(url).ConfigureAwait(false);

        // Respect non-success without throwing here (caller handles exceptions)
        resp.EnsureSuccessStatusCode();

        var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

        foreach (var line in body.Split('\n'))
        {
            var parts = line.Split(':');
            if (parts.Length != 2) continue;
            if (parts[0].Trim().Equals(suffix, StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(parts[1].Trim(), out var count))
                    return count;
            }
        }
        return 0;
    }
}