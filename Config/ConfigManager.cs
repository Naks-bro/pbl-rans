using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HoneytokenWatcher.Config
{
    public static class ConfigManager
    {
        private static readonly string ConfigDir =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RDRS");

        private static readonly string ConfigPath = Path.Combine(ConfigDir, "rdrs_config.json");

        private static readonly JsonSerializerOptions _opts = new()
        {
            WriteIndented = true,
            Converters    = { new JsonStringEnumConverter() }
        };

        public static RdrsConfig Load()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    var json = File.ReadAllText(ConfigPath);
                    return JsonSerializer.Deserialize<RdrsConfig>(json, _opts) ?? new RdrsConfig();
                }
            }
            catch { /* fall through to defaults */ }

            return new RdrsConfig();
        }

        public static void Save(RdrsConfig config)
        {
            try
            {
                Directory.CreateDirectory(ConfigDir);
                File.WriteAllText(ConfigPath, JsonSerializer.Serialize(config, _opts));
            }
            catch { }
        }
    }
}
