/*
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace Martix_Injector
{
    class Program
    {
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        static void Main(string[] args)
        {

            Console.Title = "Martix Injector";
            string currentDirectory = GetCurrentDirectory();
            var wjj = currentDirectory + "\\Martix Injector.runtimeset.dll";
            if (!File.Exists(wjj))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("文件缺失:Martix Injector.runtimeset.dll");
                Console.WriteLine("请重新下载程序后再试");
                Thread.Sleep(Timeout.Infinite);

                //string fileContent = "文件缺失:Martix Injector.runtimeset.dll";

                //string filePath = currentDirectory;
                //CreateFile(filePath);
                //WriteToFile(filePath, fileContent);
                //OpenFile(filePath);

                //Environment.Exit(0);
            }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Martix Injector : Made by wzhy233");
            Console.WriteLine("Version : 1.1\n");

            // 获取管理员权限
            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("请管理员权限来运行此程序！");
                Console.ReadKey();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("输入1自行选择，输入2加载默认");
            //Console.WriteLine("输入2加载默认");
            var pd = Console.ReadLine();

            if (pd == "1")
            {
                // 打开文件选择对话框
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("请全行输入DLL文件地址：");
                var filePath = Console.ReadLine();
                // 寻找并注入DLL到javaw进程
                InjectDLL(filePath);
            }

            if (pd == "2")
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                // 打开文件选择对话框
                //Console.WriteLine("已选择默认：");
                /*
                //var filePath = Console.ReadLine();
                string fileUrl = "https://wzhy233.c-n.icu/hack/hack.dll"; // 替换为要下载的文件 URL
                string savePath = "C:\\Downloads\\hack.dll"; // 替换为保存文件的路径

                Console.WriteLine("开始下载文件...");
                bool success = DownloadFile(fileUrl, savePath);

                if (success)
                {
                    Console.WriteLine("文件下载成功！");
                }
                else
                {
                    Console.WriteLine("文件下载失败！");
                }

                var filePath = wjj;
                // 寻找并注入DLL到javaw进程
                InjectDLL(filePath);
            }




            // 按下Q退出程序
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("按下 'Q' 键退出程序...");
            while (Console.ReadKey(true).Key != ConsoleKey.Q) { }

        }
        static string GetCurrentDirectory()
        {
            string assemblyLocation = Assembly.GetExecutingAssembly().Location;
            return Path.GetDirectoryName(assemblyLocation);
        }
        static bool IsAdministrator()
        {
            using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
            {
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
        }
        static bool DownloadFile(string fileUrl, string savePath)
        {
            try
            {
                using (WebClient client = new WebClient())
                {
                    client.DownloadFile(fileUrl, savePath);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"文件下载出错：{ex.Message}");
                return false;
            }
        }

        static void WriteToFile(string filePath, string content)
        {
            try
            {
                // 使用 StreamWriter 写入文件内容
                using (StreamWriter writer = new StreamWriter(filePath))
                {
                    writer.Write(content);
                }

                Console.WriteLine($"文件 {filePath} 写入成功！");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"写入文件时出错：{ex.Message}");
            }
        }

        static void CreateFile(string filePath)
        {
            try
            {
                // 使用 StreamWriter 创建文件并写入内容
                using (StreamWriter writer = new StreamWriter(filePath))
                {
                    // 可以在这里写入文件的内容，或者留空以创建空文件

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"创建文件时出错：{ex.Message}");
            }
        }

        static void OpenFile(string filePath)
        {
            try
            {
                // 使用 Process.Start() 方法打开文件
                Process.Start(filePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"打开文件时出错：{ex.Message}");
            }
        }

        static void InjectDLL(string dllPath)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"尝试注入 DLL: 目标[{dllPath}]");

            Process[] processes = Process.GetProcessesByName("javaw");
            if (processes.Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("未找到 Minecraft 进程！");
                return;
            }
            Console.ForegroundColor = ConsoleColor.Blue;
            IntPtr processHandle = processes[0].Handle;
            Console.WriteLine($"目标进程句柄: {processHandle}");

            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            if (loadLibraryAddr == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("获取 LibraryA 地址失败！");
                return;
            }
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"加载LibraryA ,地址: {loadLibraryAddr}");

            IntPtr argAddr = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);

            if (argAddr == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("在目标进程中分配内存失败！");
                return;
            }
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"分配内存地址: {argAddr}");

            byte[] argBytes = System.Text.Encoding.Default.GetBytes(dllPath + "\0");
            if (!WriteProcessMemory(processHandle, argAddr, argBytes, (uint)argBytes.Length, out _))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("在目标进程中写入数据失败！");
                return;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("数据写入成功！");

            IntPtr threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddr, argAddr, 0, IntPtr.Zero);
            if (threadHandle == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("在目标进程中创建远程线程失败！");
                return;
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("已成功将Hack(s)注入 Minecraft 进程");
        }

        [Flags]
        enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            Physical = 0x400000,
            LargePages = 0x20000000
        }

        [Flags]
        enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    }
}

*/

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using log4net;
using log4net.Repository;
using log4net.Config;

namespace Martix_Injector
{
    class Program
    {
        string logFileName = DateTime.Now.ToString("yy-MM-dd-HH-mm") + ".log";
        //ModifyLog4NetConfigFile(logFileName);
        private static readonly ILog log = LogManager.GetLogger(typeof(Program));
        static string currentVersion = "1.5"; // 当前版本号
        static string updateUrl = "https://gitee.com/wzhy233/Martix-Injector/raw/master/update.json"; // JSON文件的URL
        static string hwid = GetHardwareID();
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetWindowText(IntPtr hWnd, string lpString);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        static async Task Main(string[] args)
        {
            XmlConfigurator.Configure(new System.IO.FileInfo("log4net.config"));

            Console.Title = "Martix Injector";
            string currentDirectory = GetCurrentDirectory();
            var injectorDirectory = currentDirectory + "\\Martix Injector.runtimeset.dll";

            /*
            if (!File.Exists(wjj))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("文件缺失");
                Console.WriteLine("请重新下载程序后再试");
                Console.ReadKey();
                return;
            }
            */

            //Console.WriteLine(hwid);

            string Normal_Path1 = @"C:\Martix-Injector\";
            if (!Directory.Exists(Normal_Path1))
            {
                Directory.CreateDirectory(Normal_Path1);
            }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("Martix Injector : Made by ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("wzhy233");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"Version : {currentVersion} - 2024/7/16");
            Console.WriteLine("Welcome to Martix Injector\n");
            log.Info("Martix Injector : Made by wzhy233");
            log.Info($"Version : {currentVersion} - 2024/7/6");

            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Please run as Administrator！");
                log.Fatal("Please run as Administrator!");
                Console.ReadKey();
                return;
            }

            //自动更新
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            //Thread.Sleep(270);
            Console.WriteLine("Checking for Updates...");
            log.Info("Checking for Updates...");
            //Thread.Sleep(2342);
            await CheckForUpdates();

            Console.ForegroundColor = ConsoleColor.Yellow;
            //Thread.Sleep(300);
            Console.WriteLine("Please Choose:\n");
            //Thread.Sleep(600);
            Console.ForegroundColor = ConsoleColor.DarkMagenta;
            //Thread.Sleep(290);
            Console.WriteLine("[1] Use a local DLL");
            //Thread.Sleep(400);
            Console.WriteLine("[2] Use a cloud DLL");
            //Thread.Sleep(160);
            Console.WriteLine("[3] Open the folder");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("\nPlease enter your selection: ");
            Console.ForegroundColor = ConsoleColor.Gray;
            var pd = Console.ReadLine();



            if (pd == "1")
            {
                log.Info("Chose local DLL");
                Console.ForegroundColor = ConsoleColor.Yellow;
                string[] dllFiles = Directory.GetFiles(@"C:\Martix-Injector", "*.dll");
                Thread.Sleep(450);
                if (dllFiles.Length == 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\nNo DLL found available, make sure you have put your local DLL file into @C:\\Martix-Injector\\ 内\n");
                    log.Warn("No DLLs were found, make sure you have placed your local DLL file inside @C:\\Martix-Injector\\");
                    return;

                }
                Console.Write($"\n{dllFiles.Length} DLL(s) found - ");
                log.Info($"Successfully found {dllFiles.Length} local DLLs");
                //              Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("Address [@C:\\Maritx-Inector\\]:\n");
                
                for (int i = 0; i < dllFiles.Length; i++)
                {
                    var fileInfo = new FileInfo(dllFiles[i]);
                    Console.ForegroundColor = ConsoleColor.DarkMagenta;
                    //Thread.Sleep(100);
                    Console.WriteLine($"[{i + 1}] {fileInfo.Name} | Updated date: {fileInfo.LastWriteTime} | Size: {fileInfo.Length} bytes");
                }
                Console.ForegroundColor = ConsoleColor.Yellow;
                //Thread.Sleep(200);
                Console.Write("\nPlease enter the DLL you want to load: ");
                Console.ForegroundColor = ConsoleColor.Gray;
                var index = int.Parse(Console.ReadLine()) - 1;
                var selectedFilePath = dllFiles[index];
                if (!File.Exists(selectedFilePath))
                {
                    //Thread.Sleep(400);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\nThe selected file does not exist!");
                    log.Warn("The selected file does not exist");
                    Console.ReadKey();
                    return;
                }
                InjectDLL(selectedFilePath);
            }

            if (pd == "2")
            {
                log.Info("Chose cloud DLL");
                //Console.ForegroundColor = ConsoleColor.Yellow;
                //var filePath = wjj;
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\nHere are the cloud DLLs: \n");
                Console.ForegroundColor = ConsoleColor.DarkMagenta;
                //Thread.Sleep(1032);
                Console.WriteLine("[1] Leave   | 2024/4/6 |  1.12.2 Only | FML");
                //Thread.Sleep(400);
                Console.WriteLine("[2] Reflect | 2024/4/6 | 1.8x - 1.12.2| None");
                //Thread.Sleep(100);
                Console.WriteLine("[3] Vapev3  | 2024/4/6 | 1.8x - 1.12.2| FML");
                //Thread.Sleep(600);
                Console.WriteLine("[4] Ensemble| 2024/4/6 |      N/A     | N/A");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("\nPlease enter the DLL you want to load: ");
                Console.ForegroundColor = ConsoleColor.Gray;
                var DownloadDLL = Console.ReadLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                if (DownloadDLL == "1")
                {
                    Console.Write("\nSelected: ");
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.Write("Leave\n");
                    log.Info("Chose cloud DLL");
                    string savePath = @"C:\Martix-Injector\";
                    string filePath1 = savePath + "leave.dll";
                    string Downloadurl = "https://fs-im-kefu.7moor-fs1.com/ly/4d2c3f00-7d4c-11e5-af15-41bf63ae4ea0/1712394074045/leave.dll";
                    DownloadFile(Downloadurl, savePath, filePath1);
                }
                if (DownloadDLL == "2")
                {
                    Console.Write("\nSelected: ");
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.Write("Reflect\n");
                    log.Info("Chose cloud DLL");
                    string savePath = @"C:\Martix-Injector\";
                    string filePath1 = savePath + "Reflect.dll";
                    string Downloadurl = "https://fs-im-kefu.7moor-fs1.com/ly/4d2c3f00-7d4c-11e5-af15-41bf63ae4ea0/1712394074196/Reflect.dll";
                    DownloadFile(Downloadurl, savePath, filePath1);
                }
                if (DownloadDLL == "3")
                {
                    Console.Write("\nSelected: ");
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.Write("Vapev3\n");
                    log.Info("Chose cloud DLL");
                    string savePath = @"C:\Martix-Injector\";
                    string filePath1 = savePath + "vapev3.dll";
                    string Downloadurl = "https://fs-im-kefu.7moor-fs1.com/ly/4d2c3f00-7d4c-11e5-af15-41bf63ae4ea0/1712394073730/vapev3.dll";
                    DownloadFile(Downloadurl, savePath, filePath1);
                }
                if (DownloadDLL == "4")
                {
                    Console.Write("\nSelected: ");
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.Write("Ensemble\n");
                    log.Info("Chose cloud DLL");
                    string savePath = @"C:\Martix-Injector\";
                    string filePath1 = savePath + "Ensemble.dll";
                    string Downloadurl = "https://fs-im-kefu.7moor-fs1.com/ly/4d2c3f00-7d4c-11e5-af15-41bf63ae4ea0/1712394073885/Ensemble.dll";
                    DownloadFile(Downloadurl, savePath, filePath1);
                }

            }
            if (pd == "3")
            {
                string folderPath = @"C:\Martix-Injector\"; // 指定文件夹的路径

                try
                {
                    // 使用 Process.Start 方法打开文件夹
                    Process.Start("explorer.exe", folderPath);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Failed to open the folder：{ex.Message}");
                    log.Warn($"Failed to start 'explorer.exe': {ex.Message}");
                    return;
                }

            }


            Console.ForegroundColor = ConsoleColor.White;
            //Console.WriteLine("\n\n按下 'Q' 键退出程序...");

            while (Console.ReadKey(true).Key != ConsoleKey.Q) { }
        }

        static async Task CheckForUpdates()
        {
            try
            {
                // 下载并解析JSON文件
                string latestVersion = await GetLatestVersion(updateUrl);

                // 比较版本
                CompareVersions(latestVersion);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Failed to check for updates: {ex.Message}");
                log.Fatal($"Failed to check for updates: {ex.Message}");
                exitc0f();
            }
        }

        static void exitc0f()
        {
            Console.ForegroundColor = ConsoleColor.White;
            //Console.WriteLine("\n\n按下 'Q' 键退出程序...");

            while (Console.ReadKey(true).Key != ConsoleKey.Q) { Environment.Exit(0); }
            Environment.Exit(0);
        }

        static async Task<string> GetLatestVersion(string url)
        {
            using (var httpClient = new HttpClient())
            {
                using (var response = await httpClient.GetAsync(url))
                {
                    response.EnsureSuccessStatusCode();
                    string jsonContent = await response.Content.ReadAsStringAsync();

                    // 解析JSON
                    using (JsonDocument document = JsonDocument.Parse(jsonContent))
                    {
                        JsonElement root = document.RootElement;
                        if (root.TryGetProperty("version", out JsonElement versionElement))
                        {
                            return versionElement.GetString();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            throw new Exception("Failed to resolve update service\n");
                            //log.Fatal($"");
                            
                        }
                    }
                }
            }
        }

        static void CompareVersions(string latestVersion)
        {
            // 比较当前版本和最新版本
            if (latestVersion != currentVersion)
            {
                Console.ForegroundColor = ConsoleColor.DarkBlue;
                Console.Write("\nA new version was released: ");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"{latestVersion} ");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.Write("| ");
                Console.ForegroundColor = ConsoleColor.DarkBlue;
                Console.Write("Current version: ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"{currentVersion}");
                log.Warn($"Found a new version: {latestVersion} | You are on {currentVersion}");
                log.Warn("Please go to https://github.com/wzhy233/Martix-Injector to get the new version");

                Console.Write("Please go to ");
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.Write("https://github.com/wzhy233/Martix-Injector ");
                Console.ForegroundColor = ConsoleColor.Red;
                //Console.Write("或加入官方QQ群 ");
                Console.ForegroundColor = ConsoleColor.Magenta;
                //Console.Write("723757591 ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("to get the new version\n");
                exitc0f();
                //Console.WriteLine("是否立即更新？(Y/N)");

                /*
                // 等待用户输入
                string input = Console.ReadLine();
                if (input.ToLower() == "y")
                {
                    // 执行更新操作
                    Console.WriteLine("执行更新操作...");
                }
                else
                {
                    Console.WriteLine("取消更新。");
                }

                */
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\nYou are using latest version\n");
                log.Info($"You are using latest version");
            }

        }

        static string GetHardwareID()
        {
            string processorId = GetProcessorId();
            string biosId = GetBIOSId();
            string baseId = GetBaseId();

            string combinedId = processorId + biosId + baseId;

            // Hash the combined ID for added complexity
            string hashedId = CalculateMD5Hash(combinedId);

            return hashedId;
        }

        static string GetProcessorId()
        {
            string result = string.Empty;
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    result = obj["ProcessorId"].ToString();
                    break;
                }
            }
            return result;
        }

        static string GetBIOSId()
        {
            string result = string.Empty;
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    result = obj["SerialNumber"].ToString();
                    break;
                }
            }
            return result;
        }

        static string GetBaseId()
        {
            string result = string.Empty;
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    result = obj["SerialNumber"].ToString();
                    break;
                }
            }
            return result;
        }

        static string CalculateMD5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }
        static string GetCurrentDirectory()
        {
            string assemblyLocation = Assembly.GetExecutingAssembly().Location;
            return Path.GetDirectoryName(assemblyLocation);
        }



        static bool IsAdministrator()
        {
            using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
            {
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
        }

        static void DownloadFile(string url, string savePath, string injectf)
        {
            try
            {
                // 创建一个 WebClient 实例
                WebClient client = new WebClient();

                // 确保目标文件夹存在，如果不存在则创建
                if (!Directory.Exists(savePath))
                {
                    Directory.CreateDirectory(savePath);
                }

                // 从 URL 下载文件并保存到指定路径
                string fileName = Path.GetFileName(url);
                string filePath = Path.Combine(savePath, fileName);
                client.DownloadFile(url, filePath);
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\nDownloading......\n");
                log.Debug("Downloading...");
                Thread.Sleep(1231);
                Console.ForegroundColor = ConsoleColor.Green;
                log.Info("Download successful");
                Console.WriteLine("Download successful！");
                InjectDLL(injectf);
            }
            catch (Exception ex)
            {
                Thread.Sleep(400);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Failed to download：{ex.Message}");
                log.Error($"Failed to download: {ex.Message}");
                return;
            }
        }

        static void InjectDLL(string dllPath)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"\nInitializing: target-path [{dllPath}]\n");
            log.Debug($"Initializing: target-path [{dllPath}]");
            Thread.Sleep(5000);

            Process[] processes = Process.GetProcessesByName("javaw");
            Process[] zuluzulu = Process.GetProcessesByName("zulu");
            if (processes.Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
              //  Console.WriteLine("未找到 Minecraft 进程！");
                Console.WriteLine("Error while loading, Please open Minecraft to continue...\n");
                log.Error("Error while loading, Please open Minecraft to continue...");
                return;
            }


            // 输出所有javaw进程的PID和程序名称
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Found Minecraft: \n");
            log.Debug("Found Minecraft: ");
            for (int i = 0; i < processes.Length; i++)
            {
                Console.ForegroundColor = ConsoleColor.DarkMagenta;
                Process ajavawProcess = processes[i]; // Get the first javaw process
                //IntPtr processHandle1 = javawProcess.Handle;
                Console.WriteLine($"[{i + 1}] PID: {processes[i].Id} | Minecraft Process: {ajavawProcess.MainWindowTitle}\n");
                log.Debug($"[{i + 1}] PID: {processes[i].Id}, Minecraft: {ajavawProcess.MainWindowTitle}");
            }

            // 用户选择要注入的进程
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Please enter the Minecraft process number you want to inject: ");
            Console.ForegroundColor = ConsoleColor.Gray;
            int choice;
            if (!int.TryParse(Console.ReadLine(), out choice) || choice < 1 || choice > processes.Length)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nThe selected file does not exist！\n");
                log.Warn("The selected file does not exist");
                return;
            }
            Process javawProcess = processes[choice - 1];
            IntPtr mainWindowHandle = processes[choice - 1].MainWindowHandle;
            SetWindowText(mainWindowHandle, "Love From wzhy233");
            Process selectedProcess = processes[choice - 1];
            //Process selectedJavawProcess = processes[choice - 1];
            IntPtr processHandle = selectedProcess.Handle;
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"\nChose PID: {selectedProcess.Id}, Minecraft process: {javawProcess.MainWindowTitle}");
            log.Debug($"Chose PID: {selectedProcess.Id}, Minecraft process: {javawProcess.MainWindowTitle}");
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            if (loadLibraryAddr == IntPtr.Zero)
            {
                Thread.Sleep(500);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nFailed to get LibraryA address！");
                log.Error("Failed to get LibraryA address");
                Console.WriteLine("请稍后再试......\n");
                return;
            }
            Console.ForegroundColor = ConsoleColor.Blue;
           // Thread.Sleep(100);
            Console.WriteLine($"\nLoading LibraryA, address: {loadLibraryAddr}");
            log.Debug($"Loading LibraryA, address: {loadLibraryAddr}");
            IntPtr argAddr = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
            log.Debug(argAddr);
            if (argAddr == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Thread.Sleep(1500);
                Console.WriteLine("\nFailed to allocate memory in the target process！");
                log.Error("Failed to allocate memory in the target process");
                //Console.WriteLine("请稍后再试......\n");
                return;
            }
            Console.ForegroundColor = ConsoleColor.Blue;
            //Thread.Sleep(1500);
            Console.WriteLine($"\nAllocate memory address: {argAddr}");
            log.Debug($"Allocate memory address: {argAddr}");

            byte[] argBytes = System.Text.Encoding.Default.GetBytes(dllPath + "\0");
            if (!WriteProcessMemory(processHandle, argAddr, argBytes, (uint)argBytes.Length, out _))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Thread.Sleep(1900);
                Console.WriteLine("\nFailed to write data in the target process！");
                log.Error("Failed to write data in the target process");
                //Console.WriteLine("请稍后再试......\n");
                return;
            }
            Console.ForegroundColor = ConsoleColor.Green;
           // Thread.Sleep(4400);
            Console.WriteLine("\nThe data is successfully written！");
            log.Debug("The data is successfully written");
            IntPtr threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddr, argAddr, 0, IntPtr.Zero);
            if (threadHandle == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Thread.Sleep(2700);
                Console.WriteLine("\nFailed to create a remote thread in the target process！");
                log.Error("Failed to create a remote thread in the target process");
                //Console.WriteLine("请稍后再试......\n");
                return;
            }

            Console.ForegroundColor = ConsoleColor.Green;
           // Thread.Sleep(900);
            Console.WriteLine("Injected successfully");
            log.Info("Injected successfully");
            Thread.Sleep(500);
        }

        [Flags]
        enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            Physical = 0x400000,
            LargePages = 0x20000000
        }

        [Flags]
        enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    }
}

