using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;

namespace HoneytokenWatcher.UI
{
    /// <summary>
    /// Loads the embedded ransa logo (ransa logo.jpg) and vends it as
    /// System.Drawing.Icon instances for the tray and form title bar.
    /// Falls back to the programmatic GDI+ shield if the resource is missing.
    /// </summary>
    public static class ShieldIcon
    {
        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>16×16 icon for the system tray.</summary>
        public static System.Drawing.Icon Create() => MakeIcon(16);

        /// <summary>32×32 icon for form title bars / task-bar previews.</summary>
        public static System.Drawing.Icon CreateAppIcon() => MakeIcon(32);

        /// <summary>
        /// Saves a proper ICO file (PNG inside ICO, Vista+ compatible)
        /// to <paramref name="path"/>.  Used by the desktop shortcut.
        /// </summary>
        public static void SaveIco(string path, int size = 48)
        {
            try
            {
                using var bmp = LoadLogoBitmap(size) ?? DrawFallback(size);
                File.WriteAllBytes(path, ToIcoBytes(bmp));
            }
            catch { }
        }

        // ── Logo loading ──────────────────────────────────────────────────────

        /// <summary>
        /// Loads the embedded "ransa logo.jpg" at the requested pixel size.
        /// Returns null if the resource is not found (triggers fallback).
        /// </summary>
        private static Bitmap? LoadLogoBitmap(int size)
        {
            try
            {
                var asm    = Assembly.GetExecutingAssembly();
                using var stream = asm.GetManifestResourceStream(
                    "HoneytokenWatcher.ransa_logo.jpg");

                if (stream == null) return null;

                using var original = new Bitmap(stream);
                // High-quality resize to the requested icon size
                var resized = new Bitmap(size, size, PixelFormat.Format32bppArgb);
                using var g = Graphics.FromImage(resized);
                g.InterpolationMode  = InterpolationMode.HighQualityBicubic;
                g.SmoothingMode      = SmoothingMode.AntiAlias;
                g.PixelOffsetMode    = PixelOffsetMode.HighQuality;
                g.DrawImage(original, 0, 0, size, size);
                return resized;
            }
            catch { return null; }
        }

        private static System.Drawing.Icon MakeIcon(int size)
        {
            var bmp = LoadLogoBitmap(size) ?? DrawFallback(size);
            return IconFromBitmap(bmp);
        }

        // ── Fallback GDI+ shield ──────────────────────────────────────────────

        private static Bitmap DrawFallback(int size)
        {
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using var g = Graphics.FromImage(bmp);
            g.SmoothingMode      = SmoothingMode.AntiAlias;
            g.InterpolationMode  = InterpolationMode.HighQualityBicubic;
            g.PixelOffsetMode    = PixelOffsetMode.HighQuality;
            g.Clear(Color.Transparent);

            float s = size;

            // Shield polygon
            var shield = new PointF[]
            {
                new(s * 0.09f, s * 0.04f),
                new(s * 0.91f, s * 0.04f),
                new(s * 0.91f, s * 0.56f),
                new(s * 0.50f, s * 0.97f),
                new(s * 0.09f, s * 0.56f),
            };

            using (var fill = new SolidBrush(Color.FromArgb(178, 24, 24)))
                g.FillPolygon(fill, shield);

            float inset = s * 0.09f;
            var inner = new PointF[]
            {
                new(shield[0].X + inset,   shield[0].Y + inset),
                new(shield[1].X - inset,   shield[1].Y + inset),
                new(shield[2].X - inset,   shield[2].Y),
                new(shield[3].X,           shield[3].Y - inset * 1.4f),
                new(shield[4].X + inset,   shield[4].Y),
            };
            using (var dark = new SolidBrush(Color.FromArgb(12, 6, 18)))
                g.FillPolygon(dark, inner);

            using (var border = new Pen(Color.FromArgb(230, 55, 55), size > 20 ? 1.5f : 1f))
                g.DrawPolygon(border, shield);

            if (size >= 24)
            {
                float fSize = s * 0.22f;
                using var font  = new Font("Arial", fSize, FontStyle.Bold, GraphicsUnit.Pixel);
                using var brush = new SolidBrush(Color.White);
                var sf = new StringFormat
                {
                    Alignment     = StringAlignment.Center,
                    LineAlignment = StringAlignment.Center,
                };
                g.DrawString("RDRS", font, brush,
                    new RectangleF(0, s * 0.08f, s, s * 0.68f), sf);
            }
            else
            {
                using var pen = new Pen(Color.White, 1.6f)
                    { StartCap = LineCap.Round, EndCap = LineCap.Round };
                float cx = s * 0.46f;
                float y0 = s * 0.24f, ym = s * 0.48f, y1 = s * 0.74f;
                float xl = cx - s * 0.18f, xr = cx + s * 0.22f;

                g.DrawLine(pen, xl, y0, xl, y1);
                g.DrawLine(pen, xl, y0, xr - 1, y0);
                g.DrawLine(pen, xl, ym, xr - 1, ym);
                g.DrawLine(pen, xr - 1, y0, xr + 1, (y0 + ym) / 2);
                g.DrawLine(pen, xr + 1, (y0 + ym) / 2, xr - 1, ym);
                g.DrawLine(pen, xr - 1, ym, xr + 2, y1);
            }

            return bmp;
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static System.Drawing.Icon IconFromBitmap(Bitmap bmp)
        {
            using (bmp)
            {
                var hIcon = bmp.GetHicon();
                return System.Drawing.Icon.FromHandle(hIcon);
            }
        }

        /// <summary>
        /// Wraps a Bitmap as a valid ICO (PNG-in-ICO, Vista+).
        /// Format: 6-byte header + 16-byte dir entry + raw PNG bytes.
        /// </summary>
        private static byte[] ToIcoBytes(Bitmap bmp)
        {
            using var png = new MemoryStream();
            bmp.Save(png, ImageFormat.Png);
            var pngBytes = png.ToArray();

            using var ico = new MemoryStream();
            using var w   = new BinaryWriter(ico);

            w.Write((ushort)0);   // reserved
            w.Write((ushort)1);   // type = ICO
            w.Write((ushort)1);   // image count

            w.Write((byte)(bmp.Width  > 255 ? 0 : bmp.Width));
            w.Write((byte)(bmp.Height > 255 ? 0 : bmp.Height));
            w.Write((byte)0);     // color count
            w.Write((byte)0);     // reserved
            w.Write((ushort)1);   // planes
            w.Write((ushort)32);  // bits per pixel
            w.Write((uint)pngBytes.Length);
            w.Write((uint)22);    // data offset = 6 + 16

            w.Write(pngBytes);

            return ico.ToArray();
        }
    }
}
