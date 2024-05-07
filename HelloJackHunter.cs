using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace HelloJackHunter
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: HelloJackHunter.exe <path to DLL or directory> <output path>");
                return;
            }

            string inputPath = args[0];
            string outputPath = args[1];

            if (File.Exists(inputPath))
            {
                // Single file
                ProcessDll(inputPath, outputPath);
            }
            else if (Directory.Exists(inputPath))
            {
                // Directory
                foreach (string file in Directory.GetFiles(inputPath, "*.dll"))
                {
                    ProcessDll(file, outputPath);
                }
            }
            else
            {
                Console.WriteLine("Invalid path.");
            }
        }

        static void ProcessDll(string dllPath, string outputPath)
        {
            string outputFileName = Path.Combine(outputPath, Path.GetFileNameWithoutExtension(dllPath) + ".cpp");
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("#include <windows.h>");
            sb.AppendLine("#include \"pch.h\"");
            sb.AppendLine("#include <iostream>");

            try
            {
                // Call dumpbin.exe and get the output
                string dumpbinOutput = CallDumpbin(dllPath);
                // Parse exported function names
                var exportedFunctions = ParseExportedFunctions(dumpbinOutput);

                foreach (string functionName in exportedFunctions)
                {
                    string cppTemplate = GenerateCppTemplate(functionName);
                    sb.AppendLine(cppTemplate);
                }

                // Add DllMain function
                sb.AppendLine(GenerateDllMainTemplate());

                File.WriteAllText(outputFileName, sb.ToString());
                Console.WriteLine($"Generated {outputFileName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing {dllPath}: {ex.Message}");
            }
        }

        static string CallDumpbin(string dllPath)
        {
            string dumpbinPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\dumpbin.exe";

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = dumpbinPath,
                Arguments = $"/exports \"{dllPath}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(startInfo))
            {
                using (StreamReader reader = process.StandardOutput)
                {
                    return reader.ReadToEnd();
                }
            }
        }

        static HashSet<string> ParseExportedFunctions(string dumpbinOutput)
        {
            HashSet<string> functions = new HashSet<string>();
            string[] lines = dumpbinOutput.Split('\n');
            bool exportsStart = false;

            foreach (string line in lines)
            {
                if (line.Contains("ordinal hint RVA      name"))
                {
                    exportsStart = true;
                    continue;
                }

                if (exportsStart)
                {
                    Match match = Regex.Match(line, @"\s*\d+\s+\d+\s+[A-F0-9]+\s+(\S+)");
                    if (match.Success)
                    {
                        functions.Add(match.Groups[1].Value);
                    }
                }
            }

            return functions;
        }

        static string GenerateCppTemplate(string functionName)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("extern \"C\" {{\n");
            sb.AppendFormat("    __declspec(dllexport) void {0}() {{\n", functionName);
            sb.AppendFormat("        MessageBox(NULL, L\"ZephrFish DLL Hijack in {0}\", L\"Function Call\", MB_OK);\n", functionName);
            sb.AppendLine("    }");
            sb.AppendLine("}");
            return sb.ToString();
        }

        static string GenerateDllMainTemplate()
        {
            return @"
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, L""ZephrFish DLL Hijack in DLL_PROCESS_ATTACH"", L""DllMain Event"", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
        // Code for thread attachment
        break;
    case DLL_THREAD_DETACH:
        // Code for thread detachment
        break;
    case DLL_PROCESS_DETACH:
        // Code for process detachment
        break;
    }
    return TRUE;
}";
        }
    }
}
