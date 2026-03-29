using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace HoneytokenWatcher.Honeytokens
{
    /// <summary>
    /// Plants decoy files that look 100% real to ransomware:
    /// - Correct magic bytes / file headers
    /// - Real internal structure (DOCX = actual ZIP+XML, PDF = real xref)
    /// - Named with _AAAA_ prefix so they sort first → ransomware hits them first
    /// - Hidden + System attributes → invisible to normal users
    /// </summary>
    public class HoneytokenPlanter
    {
        // Ransomware-targeted directories
        private static readonly string[] TargetDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads",
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Pictures",
        };

        // Token definitions: (filename, generator)
        private readonly List<(string name, Func<byte[]> generator)> _tokenDefs = new()
        {
            ("_AAAA_resume_final.docx",       () => GenerateDocx("John Doe Resume", "Software Engineer with 5 years experience.")),
            ("_AAAA_tax_return_2024.pdf",      () => GeneratePdf("Tax Return 2024", "Gross Income: $95,000\nFederal Tax: $14,200")),
            ("_AAAA_family_vacation.jpg",      () => GenerateJpeg()),
            ("_AAAA_bank_statement.xlsx",      () => GenerateXlsx()),
            ("_AAAA_passwords_backup.txt",     () => GenerateTxt("admin:P@ssw0rd123\nwifi:HomeNetwork2024\nemail:SecurePass!")),
            ("_AAAA_project_contracts.docx",   () => GenerateDocx("Contract Agreement", "This agreement is entered into on January 1, 2024.")),
            ("_AAAA_crypto_wallet.txt",        () => GenerateTxt("Seed Phrase: apple mango river stone cloud forest echo bright flame star")),
            ("_AAAA_medical_records.pdf",      () => GeneratePdf("Medical Record", "Patient: Jane Doe\nDOB: 1985-03-12\nDiagnosis: Healthy")),
        };

        // Extensions ransomware appends to encrypted files
        private static readonly string[] StaleExtensions =
        {
            ".locked", ".encrypted", ".enc", ".wncry", ".ransom",
            ".crypt", ".crypted", ".pays", ".rdm", ".wallet", ".wnry",
        };

        // Known-good extensions for honeytoken files
        private static readonly HashSet<string> GoodExtensions =
            new(StringComparer.OrdinalIgnoreCase)
            { ".docx", ".pdf", ".jpg", ".xlsx", ".txt", ".png", ".mp4", ".bak" };

        private readonly List<string> _plantedPaths = new();

        /// <summary>
        /// Deletes stale <c>_AAAA_*</c> files that ransomware renamed/encrypted
        /// during a previous run, so fresh tokens can always be planted.
        /// </summary>
        private static void CleanStaleTokens(string dir)
        {
            try
            {
                foreach (var file in Directory.GetFiles(dir, "_AAAA_*"))
                {
                    var ext = Path.GetExtension(file);
                    bool isStale = !GoodExtensions.Contains(ext)
                        || Array.Exists(StaleExtensions,
                               s => file.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                    if (!isStale) continue;
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                        File.Delete(file);
                    }
                    catch { }
                }
            }
            catch { /* best effort — don't crash startup */ }
        }

        public List<HoneytokenFile> PlantAll()
        {
            var result = new List<HoneytokenFile>();

            foreach (var dir in TargetDirs)
            {
                if (!Directory.Exists(dir)) continue;

                // Remove any leftovers from a previous run that ransomware
                // may have renamed/encrypted (.locked, .encrypted, etc.)
                CleanStaleTokens(dir);

                // Plant 2 tokens per directory
                for (int i = 0; i < Math.Min(2, _tokenDefs.Count); i++)
                {
                    var idx = (Array.IndexOf(TargetDirs, dir) * 2 + i) % _tokenDefs.Count;
                    var (name, generator) = _tokenDefs[idx];
                    var fullPath = Path.Combine(dir, name);

                    try
                    {
                        // Strip Hidden+System from a leftover file before overwriting —
                        // WriteAllBytes throws "Access denied" on a system-attributed file
                        if (File.Exists(fullPath))
                            File.SetAttributes(fullPath, FileAttributes.Normal);

                        var bytes = generator();
                        File.WriteAllBytes(fullPath, bytes);

                        // Make invisible to users but accessible to processes
                        File.SetAttributes(fullPath,
                            FileAttributes.Hidden | FileAttributes.System);

                        // Grant BUILTIN\Users Modify rights so non-elevated processes
                        // (ransomware running in user context) can write to the file.
                        // WindowsIdentity.GetCurrent().User returns the ADMIN SID when
                        // elevated, not the standard user — so we use BuiltinUsersSid
                        // which covers all interactive users regardless of elevation.
                        try
                        {
                            var fi      = new FileInfo(fullPath);
                            var acl     = fi.GetAccessControl();
                            var usersSid = new SecurityIdentifier(
                                WellKnownSidType.BuiltinUsersSid, null);
                            acl.AddAccessRule(new FileSystemAccessRule(
                                usersSid,
                                FileSystemRights.Modify | FileSystemRights.Synchronize,
                                InheritanceFlags.None,
                                PropagationFlags.None,
                                AccessControlType.Allow));
                            fi.SetAccessControl(acl);

                            // Lower Mandatory Integrity Level from High (inherited from
                            // elevated process) to Medium so non-elevated processes
                            // (ransomware in user context) can write to the file.
                            // The DACL alone is not enough — MIC overrides it.
                            try
                            {
                                var psi = new System.Diagnostics.ProcessStartInfo
                                {
                                    FileName        = "icacls.exe",
                                    Arguments       = $"\"{fullPath}\" /setintegritylevel Medium",
                                    UseShellExecute = false,
                                    CreateNoWindow  = true
                                };
                                System.Diagnostics.Process.Start(psi)?.WaitForExit(3000);
                            }
                            catch { /* MIL set is best-effort */ }
                        }
                        catch { /* ACL grant is best-effort */ }

                        _plantedPaths.Add(fullPath);

                        result.Add(new HoneytokenFile
                        {
                            FullPath = fullPath,
                            FileName = name,
                            Directory = dir,
                            FileType = Path.GetExtension(name).TrimStart('.'),
                            FileSizeBytes = bytes.Length,
                            PlantedAt = DateTime.Now,
                            Status = TokenStatus.Watching
                        });
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[WARN] Could not plant {name} in {dir}: {ex.Message}");
                    }
                }
            }

            return result;
        }

        public void RemoveAll(List<HoneytokenFile> tokens)
        {
            foreach (var token in tokens)
            {
                try
                {
                    if (File.Exists(token.FullPath))
                    {
                        // Remove hidden/system before delete
                        File.SetAttributes(token.FullPath, FileAttributes.Normal);
                        File.Delete(token.FullPath);
                    }
                }
                catch { /* best effort */ }
            }
        }

        // ── File Generators ─────────────────────────────────────────────────

        /// <summary>
        /// Real DOCX = ZIP archive containing word/document.xml
        /// Ransomware that checks file structure will see a valid Office doc.
        /// </summary>
        private static byte[] GenerateDocx(string title, string content)
        {
            using var ms = new MemoryStream();
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                // [Content_Types].xml
                WriteZipEntry(zip, "[Content_Types].xml", @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<Types xmlns=""http://schemas.openxmlformats.org/package/2006/content-types"">
  <Default Extension=""rels"" ContentType=""application/vnd.openxmlformats-package.relationships+xml""/>
  <Default Extension=""xml"" ContentType=""application/xml""/>
  <Override PartName=""/word/document.xml"" ContentType=""application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml""/>
</Types>");

                // _rels/.rels
                WriteZipEntry(zip, "_rels/.rels", @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
  <Relationship Id=""rId1"" Type=""http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"" Target=""word/document.xml""/>
</Relationships>");

                // word/document.xml — actual content
                WriteZipEntry(zip, "word/document.xml", $@"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<w:document xmlns:w=""http://schemas.openxmlformats.org/wordprocessingml/2006/main"">
  <w:body>
    <w:p><w:r><w:rPr><w:b/></w:rPr><w:t>{title}</w:t></w:r></w:p>
    <w:p><w:r><w:t>{content}</w:t></w:r></w:p>
    <w:p><w:r><w:t>Generated: {DateTime.Now:yyyy-MM-dd}</w:t></w:r></w:p>
  </w:body>
</w:document>");

                // word/_rels/document.xml.rels
                WriteZipEntry(zip, "word/_rels/document.xml.rels", @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
</Relationships>");
            }
            return ms.ToArray();
        }

        /// <summary>
        /// Real PDF structure with valid header, xref table, and trailer.
        /// </summary>
        private static byte[] GeneratePdf(string title, string content)
        {
            var sb = new StringBuilder();
            sb.AppendLine("%PDF-1.4");
            sb.AppendLine("%âãÏÓ"); // binary comment — marks as binary PDF

            int obj1Start = sb.Length;
            sb.AppendLine("1 0 obj");
            sb.AppendLine("<< /Type /Catalog /Pages 2 0 R >>");
            sb.AppendLine("endobj");

            int obj2Start = sb.Length;
            sb.AppendLine("2 0 obj");
            sb.AppendLine("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
            sb.AppendLine("endobj");

            int obj3Start = sb.Length;
            sb.AppendLine("3 0 obj");
            sb.AppendLine("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>");
            sb.AppendLine("endobj");

            string streamContent = $"BT /F1 12 Tf 50 750 Td ({title}) Tj 0 -20 Td ({content.Replace("\n", ") Tj 0 -20 Td (")}) Tj ET";
            int obj4Start = sb.Length;
            sb.AppendLine("4 0 obj");
            sb.AppendLine($"<< /Length {streamContent.Length} >>");
            sb.AppendLine("stream");
            sb.AppendLine(streamContent);
            sb.AppendLine("endstream");
            sb.AppendLine("endobj");

            int obj5Start = sb.Length;
            sb.AppendLine("5 0 obj");
            sb.AppendLine("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
            sb.AppendLine("endobj");

            int xrefStart = sb.Length;
            sb.AppendLine("xref");
            sb.AppendLine("0 6");
            sb.AppendLine("0000000000 65535 f ");
            sb.AppendLine($"{obj1Start:D10} 00000 n ");
            sb.AppendLine($"{obj2Start:D10} 00000 n ");
            sb.AppendLine($"{obj3Start:D10} 00000 n ");
            sb.AppendLine($"{obj4Start:D10} 00000 n ");
            sb.AppendLine($"{obj5Start:D10} 00000 n ");
            sb.AppendLine("trailer");
            sb.AppendLine("<< /Size 6 /Root 1 0 R >>");
            sb.AppendLine("startxref");
            sb.AppendLine(xrefStart.ToString());
            sb.AppendLine("%%EOF");

            return Encoding.Latin1.GetBytes(sb.ToString());
        }

        /// <summary>
        /// Valid JPEG with correct SOI + APP0/JFIF header.
        /// File readers and ransomware both recognize it as a real image.
        /// </summary>
        private static byte[] GenerateJpeg()
        {
            // JFIF header: SOI + APP0 marker
            var header = new byte[]
            {
                0xFF, 0xD8,             // SOI marker
                0xFF, 0xE0,             // APP0 marker
                0x00, 0x10,             // length 16
                0x4A, 0x46, 0x49, 0x46, 0x00,  // "JFIF\0"
                0x01, 0x01,             // version 1.1
                0x00,                   // aspect ratio units
                0x00, 0x01,             // Xdensity
                0x00, 0x01,             // Ydensity
                0x00, 0x00,             // thumbnail
                // Minimal quantization table to make it parseable
                0xFF, 0xDB, 0x00, 0x43, 0x00,
                0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07,
                0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14,
                0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13,
                0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A,
                0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22,
                0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C,
                0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39,
                0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32,
                // EOI
                0xFF, 0xD9
            };
            return header;
        }

        /// <summary>
        /// Real XLSX = ZIP with xl/workbook.xml and a sheet with data.
        /// </summary>
        private static byte[] GenerateXlsx()
        {
            using var ms = new MemoryStream();
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                WriteZipEntry(zip, "[Content_Types].xml", @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<Types xmlns=""http://schemas.openxmlformats.org/package/2006/content-types"">
  <Default Extension=""rels"" ContentType=""application/vnd.openxmlformats-package.relationships+xml""/>
  <Default Extension=""xml"" ContentType=""application/xml""/>
  <Override PartName=""/xl/workbook.xml"" ContentType=""application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml""/>
  <Override PartName=""/xl/worksheets/sheet1.xml"" ContentType=""application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml""/>
</Types>");

                WriteZipEntry(zip, "_rels/.rels", @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
  <Relationship Id=""rId1"" Type=""http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"" Target=""xl/workbook.xml""/>
</Relationships>");

                WriteZipEntry(zip, "xl/workbook.xml", @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<workbook xmlns=""http://schemas.openxmlformats.org/spreadsheetml/2006/main"">
  <sheets><sheet name=""Accounts"" sheetId=""1"" r:id=""rId1"" xmlns:r=""http://schemas.openxmlformats.org/officeDocument/2006/relationships""/></sheets>
</workbook>");

                WriteZipEntry(zip, "xl/_rels/workbook.xml.rels", @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
  <Relationship Id=""rId1"" Type=""http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"" Target=""worksheets/sheet1.xml""/>
</Relationships>");

                WriteZipEntry(zip, "xl/worksheets/sheet1.xml", @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<worksheet xmlns=""http://schemas.openxmlformats.org/spreadsheetml/2006/main"">
  <sheetData>
    <row r=""1""><c r=""A1"" t=""inlineStr""><is><t>Account</t></is></c><c r=""B1"" t=""inlineStr""><is><t>Balance</t></is></c></row>
    <row r=""2""><c r=""A2"" t=""inlineStr""><is><t>Savings</t></is></c><c r=""B2""><v>48500</v></c></row>
    <row r=""3""><c r=""A3"" t=""inlineStr""><is><t>Checking</t></is></c><c r=""B3""><v>12300</v></c></row>
  </sheetData>
</worksheet>");
            }
            return ms.ToArray();
        }

        private static byte[] GenerateTxt(string content)
            => Encoding.UTF8.GetBytes(content);

        private static void WriteZipEntry(ZipArchive zip, string name, string content)
        {
            var entry = zip.CreateEntry(name, CompressionLevel.Fastest);
            using var w = new StreamWriter(entry.Open());
            w.Write(content);
        }
    }
}
