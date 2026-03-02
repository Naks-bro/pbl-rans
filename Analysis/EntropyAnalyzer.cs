using System;
using System.IO;

namespace HoneytokenWatcher.Analysis
{
    public static class EntropyAnalyzer
    {
        /// <summary>
        /// Calculates Shannon entropy of a byte array.
        /// Returns bits per byte in the range 0.0 – 8.0.
        ///
        /// Reference values:
        ///   Plain English text  ≈ 3.5 – 5.0
        ///   ZIP / JPEG          ≈ 7.0 – 7.5  (already compressed)
        ///   AES / ChaCha20      ≈ 7.9 – 8.0  (looks like random noise)
        ///
        /// Threshold of 7.2 catches ransomware encryption while avoiding
        /// false positives from normal compressed files.
        /// </summary>
        public static double Calculate(byte[] data)
        {
            if (data.Length == 0) return 0.0;

            var freq = new int[256];
            foreach (var b in data) freq[b]++;

            double entropy = 0.0;
            double len = data.Length;
            foreach (var f in freq)
            {
                if (f == 0) continue;
                double p = f / len;
                entropy -= p * Math.Log2(p);
            }

            return Math.Round(entropy, 4);
        }

        /// <summary>
        /// Opens the file (with ReadWrite share so it can be open by other processes)
        /// and returns its Shannon entropy, or -1.0 if unreadable.
        /// </summary>
        public static double CalculateForFile(string path)
        {
            try
            {
                using var fs = new FileStream(
                    path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                var bytes = new byte[fs.Length];
                _ = fs.Read(bytes, 0, bytes.Length);
                return Calculate(bytes);
            }
            catch { return -1.0; }
        }
    }
}
