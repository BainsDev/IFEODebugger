using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace IFEODebugger
{
    internal static class Program
    {
        private static readonly SemaphoreSlim KeepAlive = new SemaphoreSlim(0, 1);
        private const string TargetProcessName = "LeagueClientUx.exe";

        private static void KillOnExit(object process)
        {
            ((Process) process).WaitForExit();
            Console.WriteLine($"{TargetProcessName} quit.");
            Thread.Sleep(1000);
            KeepAlive.Release();
        }

        private static void DebuggerThread(object indata)
        {
            var a = (Tuple<string, string>) indata;

            var application = a.Item1;
            var commandLine = a.Item2;
            var sInfo = new STARTUPINFO();
            if (!CreateProcess(application, commandLine, IntPtr.Zero, IntPtr.Zero, false, 0x00000002, IntPtr.Zero, null, ref sInfo, out var pInfo)) throw new Win32Exception();

            new Thread(KillOnExit) {IsBackground = true, Name = "KillOnExitThread"}.Start(Process.GetProcessById(pInfo.dwProcessId)); 

            while (true)
            {
                // wait for a debug event
                if (!WaitForDebugEvent(out var evt, -1))
                    throw new Win32Exception();
                // return DBG_CONTINUE for all events but the exception type
                var continueFlag = DBG_CONTINUE;
                if (evt.dwDebugEventCode == DebugEventType.EXCEPTION_DEBUG_EVENT)
                    continueFlag = DBG_EXCEPTION_NOT_HANDLED;
                if (!ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueFlag))
                    throw new Win32Exception();
            }
        }

        private static void Main(string[] args)
        {
            if (args.Length > 0)
            { 
                var app = args[0];
                var cmdLine = "\"" + args.Skip(1).Aggregate((x, y) => x + "\" \"" + y) + "\"";

                var auth = Regex.Match(cmdLine, "(\"--remoting-auth-token=)([^\"]*)(\")").Groups[2].Value;
                var port = int.Parse(Regex.Match(cmdLine, "(\"--app-port=)([^\"]*)(\")").Groups[2].Value);

                Console.WriteLine("Using Port: " + port);
                Console.WriteLine("Using Auth: " + auth);

                cmdLine = cmdLine.Replace("\"--no-proxy-server\"", "");

                new Thread(DebuggerThread) {IsBackground = true, Name = "DebuggerThread"}.Start(new Tuple<string, string>(app, cmdLine));
                KeepAlive.Wait();
            }
            else
            {
                Menu();
            }
        }

        private static void Menu()
        {
            RegistryKey registryKey = null;
            var location = Assembly.GetExecutingAssembly().Location;
            try
            {
                registryKey =
                    Registry.LocalMachine.CreateSubKey(
                        @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" +
                        TargetProcessName,true);
            }
            catch (UnauthorizedAccessException)
            {
                try
                {
                    new Process
                    {
                        StartInfo =
                        {
                            FileName = Assembly.GetExecutingAssembly().Location,
                            UseShellExecute = true,
                            Verb = "runas"
                        }
                    }.Start();
                    Environment.Exit(0);
                }
                catch
                {
                    Console.WriteLine("Access denied.");
                    Thread.Sleep(1000);
                    Environment.Exit(1);
                }
            }

            var selected = 0;
            const int maxSelected = 2;

            while (true)
            {
                Console.Clear();
                Console.ResetColor();
                Console.CursorVisible = false;
                Console.Write("Currently hooked to: ");

                var hookedTo = (registryKey?.GetValue("debugger") ?? "Nothing.").ToString()
                    .Replace(location, "This program.");

                if (hookedTo == "This program.")
                    Console.ForegroundColor = ConsoleColor.Green;
                else if (hookedTo != "Nothing.")
                    Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(hookedTo);

                if (selected == 0) Console.ForegroundColor = ConsoleColor.White;
                else Console.ResetColor();
                Console.WriteLine($"{(selected == 0 ? "-->" : "   ")} Register {TargetProcessName} debugger IEFO.");

                if (selected == 1) Console.ForegroundColor = ConsoleColor.White;
                else Console.ResetColor();
                Console.WriteLine($"{(selected == 1 ? "-->" : "   ")} Unregister {TargetProcessName} debugger IEFO.");

                if (selected == 2) Console.ForegroundColor = ConsoleColor.White;
                else Console.ResetColor();
                Console.WriteLine($"{(selected == 2 ? "-->" : "   ")} Exit.");

                var redraw = false;
                while (!redraw)
                    switch (Console.ReadKey(true).Key)
                    {
                        case ConsoleKey.UpArrow:
                            if (selected != (selected = Math.Max(selected - 1, 0)))
                                redraw = true;
                            break;

                        case ConsoleKey.DownArrow:
                            if (selected != (selected = Math.Min(selected + 1, maxSelected)))
                                redraw = true;
                            break;

                        case ConsoleKey.Enter:
                            redraw = true;
                            switch (selected)
                            {
                                case 0:
                                    registryKey?.SetValue("debugger", location); 
                                    break;

                                case 1:
                                    registryKey?.DeleteValue("debugger");
                                    break;

                                case 2:
                                    Environment.Exit(0);
                                    break;
                            }
                            break;
                    }
            }
        }

        #region Windows API

        // ReSharper disable All
        private const int DBG_CONTINUE = 0x00010002;

        private const int DBG_EXCEPTION_NOT_HANDLED = unchecked((int) 0x80010001);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("Kernel32.dll", SetLastError = true)]
        private static extern bool WaitForDebugEvent([Out] out DEBUG_EVENT lpDebugEvent, int dwMilliseconds);

        [DllImport("Kernel32.dll", SetLastError = true)]
        private static extern bool ContinueDebugEvent(int dwProcessId, int dwThreadId, int dwContinueStatus);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        private struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum DebugEventType
        {
            CREATE_PROCESS_DEBUG_EVENT =
                3, //Reports a create-process debugging event. The value of u.CreateProcessInfo specifies a CREATE_PROCESS_DEBUG_INFO structure.

            CREATE_THREAD_DEBUG_EVENT =
                2, //Reports a create-thread debugging event. The value of u.CreateThread specifies a CREATE_THREAD_DEBUG_INFO structure.

            EXCEPTION_DEBUG_EVENT =
                1, //Reports an exception debugging event. The value of u.Exception specifies an EXCEPTION_DEBUG_INFO structure.

            EXIT_PROCESS_DEBUG_EVENT =
                5, //Reports an exit-process debugging event. The value of u.ExitProcess specifies an EXIT_PROCESS_DEBUG_INFO structure.

            EXIT_THREAD_DEBUG_EVENT =
                4, //Reports an exit-thread debugging event. The value of u.ExitThread specifies an EXIT_THREAD_DEBUG_INFO structure.

            LOAD_DLL_DEBUG_EVENT =
                6, //Reports a load-dynamic-link-library (DLL) debugging event. The value of u.LoadDll specifies a LOAD_DLL_DEBUG_INFO structure.

            OUTPUT_DEBUG_STRING_EVENT =
                8, //Reports an output-debugging-string debugging event. The value of u.DebugString specifies an OUTPUT_DEBUG_STRING_INFO structure.

            RIP_EVENT =
                9, //Reports a RIP-debugging event (system debugging error). The value of u.RipInfo specifies a RIP_INFO structure.

            UNLOAD_DLL_DEBUG_EVENT =
                7 //Reports an unload-DLL debugging event. The value of u.UnloadDll specifies an UNLOAD_DLL_DEBUG_INFO structure.
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DEBUG_EVENT
        {
            public readonly DebugEventType dwDebugEventCode;
            public readonly int dwProcessId;
            public readonly int dwThreadId;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 86, ArraySubType = UnmanagedType.U1)]
            private readonly byte[] debugInfo;
        }

        // ReSharper restore All

        #endregion Windows API
    }
}