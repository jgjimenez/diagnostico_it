using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management; 
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices; 
using System.Security;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;

public class Program
{
    // --- CLASES DE DATOS (MODELOS) ---
    public class ServiceStatus
    {
        public string Name { get; set; }
        public ServiceControllerStatus Status { get; set; }
        public ServiceStartMode StartType { get; set; }
        public string DisplayStatus { get; set; }
        public string DisplayStartType { get; set; }
    }

    public class NetworkAdapterInfo
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public OperationalStatus Status { get; set; }
        public long LinkSpeed { get; set; }
    }

    public class FirewallRule
    {
        public string Name { get; set; }
        public string Group { get; set; }
        public string Direction { get; set; } // "Inbound" o "Outbound"
        public string Action { get; set; }    // "Allow" o "Block"
        public string Enabled { get; set; }   // "True" o "False"
        public string Profile { get; set; }   // "Domain", "Private", "Public"
        public string LocalAddress { get; set; }
        public string RemoteAddress { get; set; }
        public string Protocol { get; set; }
        public string LocalPort { get; set; }
        public string RemotePort { get; set; }
        public string Application { get; set; } // Ruta del programa
    }

    public static void ListAllServices()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== LISTA DE TODOS LOS SERVICIOS DE WINDOWS ===");
        Console.ResetColor();

        try
        {
            ServiceController[] services = ServiceController.GetServices();

            Console.WriteLine($"Total de servicios encontrados: {services.Length}");
            Console.WriteLine("---------------------------------------------");

            foreach (ServiceController service in services)
            {
                try
                {
                    service.Refresh(); // Actualizar el estado actual

                    // Obtener nombres y descripción desde el registro
                    string serviceName = service.ServiceName;
                    string displayName = service.DisplayName;
                    string description = GetServiceDescriptionFromRegistry(serviceName);

                    // Obtener estado y tipo de inicio
                    ServiceControllerStatus status = service.Status;
                    ServiceStartMode startType;

                    try
                    {
                        startType = service.StartType;
                    }
                    catch (System.InvalidOperationException)
                    {
                        startType = ServiceStartMode.Disabled; // Si no hay permisos
                    }

                    // Mostrar información
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine($"\n[ {displayName} ]");
                    Console.ResetColor();
                    Console.WriteLine($"  Nombre Interno: {serviceName}");
                    Console.WriteLine($"  Descripción: {(string.IsNullOrEmpty(description) ? "N/A" : description)}");
                    Console.Write($"  Estado: ");
                    Console.ForegroundColor = status == ServiceControllerStatus.Running ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.Write($"{status}");
                    Console.ResetColor();
                    Console.WriteLine($" | Tipo de Inicio: {startType}");
                    Console.WriteLine("---------------------------------------------");
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error al acceder al servicio {service.ServiceName}: {ex.Message}");
                    Console.ResetColor();
                }
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener la lista de servicios: {ex.Message}");
            Console.ResetColor();
            Console.WriteLine("Asegúrese de ejecutar la aplicación como Administrador.");
        }
    }

    private static string GetServiceDescriptionFromRegistry(string serviceName)
    {
        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}"))
            {
                if (key != null)
                {
                    object description = key.GetValue("Description");
                    return description?.ToString() ?? string.Empty;
                }
            }
        }
        catch (SecurityException)
        {
            return "[Acceso denegado al registro]";
        }
        catch (Exception ex)
        {
            return $"[Error: {ex.Message}]";
        }
        return string.Empty;
    }

    // --- MÉTODOS DE LÓGICA (FUNCIONES) ---

    // Función auxiliar para obtener el estado de un servicio
    public static ServiceStatus GetServiceStatus(string serviceName)
    {
        ServiceStatus status = new ServiceStatus { Name = serviceName };
        try
        {
            ServiceController service = new ServiceController(serviceName);
            service.Refresh(); // Asegurarse de obtener el estado actual
            status.Status = service.Status;
            status.StartType = service.StartType;

            status.DisplayStatus = status.Status.ToString();
            status.DisplayStartType = status.StartType.ToString();
        }
        catch (InvalidOperationException) // Servicio no encontrado
        {
            status.DisplayStatus = "No encontrado";
            status.DisplayStartType = "N/A";
        }
        catch (Exception ex)
        {
            status.DisplayStatus = $"Error: {ex.Message}";
            status.DisplayStartType = "N/A";
        }
        return status;
    }

    // --- P/Invoke para obtener información de puertos y PIDs ---
    public enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
        public MIB_TCPROW_OWNER_PID[] table;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TCP_TABLE_CLASS tcpTableClass, uint reserved);

    public static List<Tuple<int, int>> GetActiveTcpListenersWithPid()
    {
        List<Tuple<int, int>> activeListeners = new List<Tuple<int, int>>();
        int bufferSize = 0;

        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_LISTENER, 0);

        IntPtr pTcpTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedTcpTable(pTcpTable, ref bufferSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_LISTENER, 0);
            if (ret != 0)
            {
                return activeListeners;
            }

            uint dwNumEntries = (uint)Marshal.ReadInt32(pTcpTable);
            IntPtr rowPtr = (IntPtr)((long)pTcpTable + Marshal.SizeOf(typeof(uint)));

            for (int i = 0; i < dwNumEntries; i++)
            {
                MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));

                const uint TCP_STATE_LISTEN = 2; // Estado LISTEN en MIB_TCP_STATE_ENUM
                if (tcpRow.dwState == TCP_STATE_LISTEN)
                {
                    ushort rawNetworkOrderPort = (ushort)tcpRow.dwLocalPort;
                    short hostOrderPortSigned = IPAddress.NetworkToHostOrder((short)rawNetworkOrderPort);
                    int port = (int)(ushort)hostOrderPortSigned;
                    activeListeners.Add(Tuple.Create(port, (int)tcpRow.dwOwningPid));
                }

                rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pTcpTable);
        }

        return activeListeners;
    }


    // 1. Verificar Información del Sistema Operativo
    public static void CheckOperatingSystemInfo()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== INFORMACIÓN DEL SISTEMA OPERATIVO ===");
        Console.ResetColor();

        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Caption, Version, BuildNumber, OSArchitecture FROM Win32_OperatingSystem");
            ManagementObject os = searcher.Get().Cast<ManagementObject>().FirstOrDefault();

            if (os != null)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  Nombre del SO: {os["Caption"]}");
                Console.WriteLine($"  Versión: {os["Version"]}");
                Console.WriteLine($"  Número de Build: {os["BuildNumber"]}");
                Console.WriteLine($"  Arquitectura: {os["OSArchitecture"]}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  No se pudo obtener la información del sistema operativo.");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener información del sistema operativo: {ex.Message}");
            Console.ResetColor();
        }
    }

    // 2. Verificar Información del Procesador
    public static void CheckProcessorInfo()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== INFORMACIÓN DEL PROCESADOR ===");
        Console.ResetColor();

        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor");
            foreach (ManagementObject processor in searcher.Get())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  Nombre: {processor["Name"]}");
                Console.WriteLine($"  Núcleos Físicos: {processor["NumberOfCores"]}");
                Console.WriteLine($"  Procesadores Lógicos: {processor["NumberOfLogicalProcessors"]}");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener información del procesador: {ex.Message}");
            Console.ResetColor();
        }
    }

    // 3. Verificar Tiempo de Actividad del Sistema
    public static void CheckSystemUptime()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== TIEMPO DE ACTIVIDAD DEL SISTEMA ===");
        Console.ResetColor();

        try
        {
            // Uptime en milisegundos
            TimeSpan uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  Sistema activo por: {uptime.Days} días, {uptime.Hours} horas, {uptime.Minutes} minutos, {uptime.Seconds} segundos.");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener el tiempo de actividad del sistema: {ex.Message}");
            Console.ResetColor();
        }
    }

    // 4. Verificar Información de Dominio / Grupo de Trabajo
    public static void CheckDomainWorkgroupInfo()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== INFORMACIÓN DE DOMINIO / GRUPO DE TRABAJO ===");
        Console.ResetColor();

        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
            ManagementObject computer = searcher.Get().Cast<ManagementObject>().FirstOrDefault();

            if (computer != null)
            {
                bool partOfDomain = (bool)computer["PartOfDomain"];
                string domainStatus = partOfDomain ? $"Dominio: {computer["Domain"]}" : $"Grupo de Trabajo: {computer["Workgroup"]}";

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(domainStatus);
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("No se pudo obtener la información de dominio/grupo de trabajo.");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener información de dominio/grupo de trabajo: {ex.Message}");
            Console.ResetColor();
        }
    }

    // 5. Verificar estado de la Licencia de Windows
    public static void CheckWindowsLicenseActivation()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== ESTADO DE LA LICENCIA DE WINDOWS ===");
        Console.ResetColor();

        try
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"slmgr /dlv\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(startInfo))
            {
                if (process == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error: No se pudo iniciar el proceso de PowerShell.");
                    Console.ResetColor();
                    return;
                }

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit(15000);

                if (!string.IsNullOrWhiteSpace(error))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error al ejecutar slmgr /dlv en PowerShell: {error.Trim()}");
                    Console.ResetColor();
                    Console.WriteLine("  Asegúrese de ejecutar la aplicación como Administrador.");
                }
                else if (!string.IsNullOrWhiteSpace(output))
                {
                    Console.WriteLine("Información de Licencia de Windows:");

                    Match activationStatusMatch = Regex.Match(output, @"Estado de la licencia: (.+)", RegexOptions.Multiline);
                    string activationStatus = activationStatusMatch.Success ? activationStatusMatch.Groups[1].Value.Trim() : "No encontrado";

                    Match descriptionMatch = Regex.Match(output, @"Descripción: (.+)", RegexOptions.Multiline);
                    string description = descriptionMatch.Success ? descriptionMatch.Groups[1].Value.Trim() : "No encontrado";

                    Match productKeyChannelMatch = Regex.Match(output, @"Canal de clave de producto: (.+)", RegexOptions.Multiline);
                    string productKeyChannel = productKeyChannelMatch.Success ? productKeyChannelMatch.Groups[1].Value.Trim() : "No encontrado";

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"  Estado de Activación: {activationStatus}");
                    Console.WriteLine($"  Descripción: {description}");
                    Console.WriteLine($"  Canal de Clave: {productKeyChannel}");

                    if (productKeyChannel.Contains("VOLUME", StringComparison.OrdinalIgnoreCase) ||
                        productKeyChannel.Contains("GVLK", StringComparison.OrdinalIgnoreCase) ||
                        productKeyChannel.Contains("KMS", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("  => Es probable que esta sea una licencia de volumen o activada por KMS (no minorista/OEM).");
                    }
                    else if (productKeyChannel.Contains("RETAIL", StringComparison.OrdinalIgnoreCase) ||
                             productKeyChannel.Contains("OEM", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("  => Esta es una licencia minorista (Retail) u OEM (original del fabricante).");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("  => No se pudo determinar el tipo de licencia (posiblemente un estado inusual).");
                    }

                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("slmgr /dlv no devolvió información. ¿El sistema está activado o el comando no se pudo ejecutar correctamente?");
                    Console.ResetColor();
                }
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al verificar la licencia de Windows: {ex.Message}");
            Console.ResetColor();
            Console.WriteLine("  Asegúrese de ejecutar la aplicación como Administrador.");
        }
    }


    // 6. Verificar TPM (Trusted Platform Module)
    public static void CheckTpmInfo()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== INFORMACIÓN DE TPM (TRUSTED PLATFORM MODULE) ===");
        Console.ResetColor();

        try
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "Get-TPM",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(startInfo))
            {
                if (process == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error: No se pudo iniciar el proceso de PowerShell.");
                    Console.ResetColor();
                    return;
                }

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit(10000);

                if (!string.IsNullOrWhiteSpace(error))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error al ejecutar Get-TPM en PowerShell: {error.Trim()}");
                    Console.ResetColor();
                    Console.WriteLine("  Asegúrese de que el módulo TrustedPlatformModule esté disponible y PowerShell pueda ejecutar cmdlets.");
                }
                else if (!string.IsNullOrWhiteSpace(output))
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("TPM Detectado vía PowerShell (Get-TPM):");

                    Regex tpmRegex = new Regex(@"^(?<Property>[a-zA-Z]+)\s*:\s*(?<Value>.*)$", RegexOptions.Multiline);
                    MatchCollection matches = tpmRegex.Matches(output);

                    bool foundInfo = false;
                    foreach (Match match in matches)
                    {
                        string prop = match.Groups["Property"].Value.Trim();
                        string val = match.Groups["Value"].Value.Trim();

                        switch (prop)
                        {
                            case "TpmPresent": Console.WriteLine($"  TPM Presente: {val}"); foundInfo = true; break;
                            case "TpmReady": Console.WriteLine($"  TPM Listo: {val}"); foundInfo = true; break;
                            case "TpmEnabled": Console.WriteLine($"  TPM Habilitado: {val}"); foundInfo = true; break;
                            case "TpmActivated": Console.WriteLine($"  TPM Activado: {val}"); foundInfo = true; break;
                            case "SpecVersion": Console.WriteLine($"  Versión de Especificación (TPM): {val}"); foundInfo = true; break;
                            case "ManufacturerVersion": Console.WriteLine($"  Versión del Fabricante (Firmware): {val}"); foundInfo = true; break;
                            case "ManufacturerIdTxt": Console.WriteLine($"  Fabricante: {val}"); foundInfo = true; break;
                            case "ManufacturerVersionFull20": Console.WriteLine($"  Versión Completa del Fabricante: {val}"); foundInfo = true; break;
                        }
                    }

                    if (!foundInfo)
                    {
                        Console.WriteLine("  No se pudo extraer información clave. Salida completa de Get-TPM:");
                        Console.WriteLine(output);
                    }
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Get-TPM no devolvió información. TPM no encontrado o no inicializado correctamente.");
                    Console.ResetColor();
                }
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener información de TPM: {ex.Message}");
            Console.ResetColor();
            Console.WriteLine("  Asegúrese de ejecutar la aplicación como Administrador.");
        }
    }

    // 7. Verificar servicios clave (incluyendo TCP/IP y otros esenciales)
    public static void CheckEssentialNetworkServices()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== SERVICIOS DE RED ESENCIALES ===");
        Console.ResetColor();

        string[] networkServices = {
            "Dhcp", "Dnscache", "Netman", "NlaSvc", "nsi",
            "NetBIOS", "WlanSvc", "LanmanWorkstation", "LanmanServer",
            "Tcpip", "Netlogon", "RpcSs", "TermService"
        };

        foreach (string serviceName in networkServices)
        {
            ServiceStatus status = GetServiceStatus(serviceName);
            Console.Write($"{status.Name}: ");
            Console.ForegroundColor = (status.Status == ServiceControllerStatus.Running) ? ConsoleColor.Green : ConsoleColor.Red;
            Console.Write($"Estado={status.DisplayStatus}");
            Console.ResetColor();
            Console.WriteLine($" | Inicio={status.DisplayStartType}");
        }
    }

    // 8. Verificar adaptadores de red
    public static void CheckNetworkAdapters()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== ADAPTADORES DE RED ===");
        Console.ResetColor();

        try
        {
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            if (adapters.Length > 0)
            {
                foreach (NetworkInterface adapter in adapters)
                {
                    if (adapter.OperationalStatus == OperationalStatus.Up &&
                        adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        adapter.NetworkInterfaceType != NetworkInterfaceType.Tunnel &&
                        adapter.Speed > 0)
                    {
                        Console.WriteLine($"Nombre: {adapter.Name}");
                        Console.WriteLine($"  Descripción: {adapter.Description}");
                        Console.WriteLine($"  Estado: {adapter.OperationalStatus}");
                        Console.WriteLine($"  Velocidad: {(adapter.Speed / 1000000.0):N2} Mbps");
                        Console.WriteLine("---");
                    }
                }
            }
            else
            {
                Console.WriteLine("No se encontraron adaptadores de red activos.");
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener adaptadores de red: {ex.Message}");
            Console.ResetColor();
        }
    }

    // 9. Verificar Servidores DNS y Direcciones IP (IPv4/IPv6) / Puerta de Enlace
    public static void CheckIPAndDNSInfo()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== DIRECCIONES IP Y DNS / PUERTAS DE ENLACE ===");
        Console.ResetColor();

        try
        {
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface adapter in adapters)
            {
                if (adapter.OperationalStatus == OperationalStatus.Up &&
                    adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                    adapter.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine($"\n--- Adaptador: {adapter.Name} ({adapter.Description}) ---");
                    Console.ResetColor();

                    IPInterfaceProperties ipProps = adapter.GetIPProperties();

                    Console.WriteLine("  Direcciones IP:");
                    bool hasIp = false;
                    foreach (UnicastIPAddressInformation ip in ipProps.UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork ||
                            ip.Address.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"    - {ip.Address} (Familia: {ip.Address.AddressFamily})");
                            Console.ResetColor();
                            hasIp = true;
                        }
                    }
                    if (!hasIp)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("    No se encontraron direcciones IP para este adaptador.");
                        Console.ResetColor();
                    }

                    Console.WriteLine("  Servidores DNS:");
                    if (ipProps.DnsAddresses.Count > 0)
                    {
                        foreach (System.Net.IPAddress dns in ipProps.DnsAddresses)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"    - {dns}");
                            Console.ResetColor();
                        }
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("    No se encontraron servidores DNS para este adaptador.");
                        Console.ResetColor();
                    }

                    Console.WriteLine("  Puertas de Enlace:");
                    if (ipProps.GatewayAddresses.Count > 0)
                    {
                        foreach (GatewayIPAddressInformation gateway in ipProps.GatewayAddresses)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"    - {gateway.Address}");
                            Console.ResetColor();
                        }
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("    No se encontró puerta de enlace para este adaptador.");
                        Console.ResetColor();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener información de IP y DNS: {ex.Message}");
            Console.ResetColor();
        }
    }

    // 10. Verificar Múltiples Direcciones DNS por Adaptador
    public static void CheckMultipleDNSAddresses()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== VERIFICACIÓN DE MÚLTIPLES DIRECCIONES DNS ===");
        Console.ResetColor();

        try
        {
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            bool potentialConflictFound = false;

            foreach (NetworkInterface adapter in adapters)
            {
                if (adapter.OperationalStatus == OperationalStatus.Up &&
                    adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                    adapter.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                {
                    IPInterfaceProperties ipProps = adapter.GetIPProperties();
                    var dnsAddresses = ipProps.DnsAddresses;

                    if (dnsAddresses.Count > 1)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"  ADVERTENCIA: Adaptador '{adapter.Name}' ({adapter.Description}) tiene MÚLTIPLES servidores DNS configurados:");
                        potentialConflictFound = true;
                        foreach (System.Net.IPAddress dns in dnsAddresses)
                        {
                            Console.WriteLine($"    - {dns}");
                        }
                        Console.WriteLine("    Esto puede causar conflictos de resolución de nombres o retrasos si los servidores no están sincronizados o accesibles.");
                        Console.ResetColor();
                    }
                    else if (dnsAddresses.Count == 1)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"  Adaptador '{adapter.Name}' ({adapter.Description}) tiene 1 servidor DNS: {dnsAddresses[0]}. (OK)");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.WriteLine($"  Adaptador '{adapter.Name}' ({adapter.Description}) no tiene servidores DNS configurados explícitamente.");
                        Console.ResetColor();
                    }
                    Console.WriteLine("  ---"); // Separador entre adaptadores
                }
            }

            if (!potentialConflictFound)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  No se encontraron adaptadores con múltiples direcciones DNS configuradas que pudieran generar conflictos.");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  Se recomienda revisar los adaptadores listados arriba para posibles configuraciones de DNS redundantes o conflictivas.");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al verificar múltiples direcciones DNS: {ex.Message}");
            Console.ResetColor();
        }
    }


    // 11. Verificar perfil del Firewall (usando WMI)
    public static void CheckFirewallProfile()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== CONFIGURACIÓN FIREWALL ===");
        Console.ResetColor();

        try
        {
            ManagementObjectSearcher profileSearcher = new ManagementObjectSearcher("root\\StandardCimv2", "SELECT * FROM MSFT_NetFirewallProfile");

            foreach (ManagementObject queryObj in profileSearcher.Get())
            {
                string name = queryObj["Name"]?.ToString();
                bool enabled = Convert.ToBoolean(queryObj["Enabled"]);
                string status = enabled ? "Activado" : "Desactivado";

                Console.Write($"{name}: ");
                Console.ForegroundColor = enabled ? ConsoleColor.Green : ConsoleColor.Red;
                Console.WriteLine(status);
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener perfiles de firewall: {ex.Message}");
            Console.ResetColor();
            Console.WriteLine("Asegúrese de ejecutar la aplicación como Administrador.");
        }
    }

    // 12. Verificar Configuración de Descubrimiento de Red y Servicios Relacionados
    public static void CheckNetworkDiscovery()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== CONFIGURACIÓN Y SERVICIOS DE DESCUBRIMIENTO DE RED ===");
        Console.ResetColor();

        // a. Perfil de conexión de red (Público/Privado/Dominio)
        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\StandardCimv2", "SELECT * FROM MSFT_NetConnectionProfile");
            ManagementObject profile = searcher.Get().Cast<ManagementObject>().FirstOrDefault();

            if (profile != null && profile["NetworkCategory"] != null)
            {
                UInt32 categoryCode = (UInt32)profile["NetworkCategory"];
                string category = "";
                switch (categoryCode)
                {
                    case 0: category = "Público"; break;
                    case 1: category = "Privado"; break;
                    case 2: category = "DominioAutenticado"; break;
                    default: category = "Desconocido"; break;
                }

                string discoveryStatus = (category == "Privado" || category == "DominioAutenticado") ?
                                         "Probablemente habilitado (perfil " + category + ")" :
                                         "Probablemente deshabilitado (perfil " + category + ")";

                Console.WriteLine($"  Perfil de Red Actual: {category}");
                Console.WriteLine($"  Descubrimiento de Red: {discoveryStatus}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  No se pudo determinar el perfil de red actual.");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener perfil de red: {ex.Message}");
            Console.ResetColor();
            Console.WriteLine("Asegúrese de ejecutar la aplicación como Administrador.");
        }

        // b. Estado de los servicios de descubrimiento de red
        Console.WriteLine("\n  Estado de servicios clave para el descubrimiento de red:");
        string[] discoveryServices = {
            "FDResPub",       // Publicación de recursos de función
            "SSDPSrv",        // Descubrimiento SSDP
            "P2PIMSvc",       // Agrupación de redes de mismo nivel (Peer Name Resolution Protocol)
            "PNRPsvc"         // Protocolo de resolución de nombres de mismo nivel
        };

        foreach (string serviceName in discoveryServices)
        {
            ServiceStatus status = GetServiceStatus(serviceName);
            Console.Write($"  {status.Name}: ");
            Console.ForegroundColor = (status.Status == ServiceControllerStatus.Running) ? ConsoleColor.Green : ConsoleColor.Red;
            Console.Write($"Estado={status.DisplayStatus}");
            Console.ResetColor();
            Console.WriteLine($" | Inicio={status.DisplayStartType}");
        }
    }

    // 13. Verificar Procesos escuchando puertos TCP
    public static void CheckTcpListeningProcesses()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== PROCESOS ESCUCHANDO PUERTOS TCP ===");
        Console.ResetColor();

        try
        {
            List<Tuple<int, int>> listeners = GetActiveTcpListenersWithPid();
            if (listeners.Count > 0)
            {
                Console.WriteLine("  Puertos TCP en estado LISTEN y sus PIDs asociados:");
                var processList = Process.GetProcesses().ToDictionary(p => p.Id, p => p.ProcessName);

                foreach (var listener in listeners)
                {
                    int port = listener.Item1;
                    int pid = listener.Item2;
                    string processName = processList.TryGetValue(pid, out string name) ? name : "Desconocido";

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"    Puerto: {port} -> PID: {pid} (Proceso: {processName})");
                    Console.ResetColor();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  No se encontraron procesos escuchando puertos TCP.");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener procesos escuchando puertos TCP: {ex.Message}");
            Console.ResetColor();
            Console.WriteLine("  Asegúrese de ejecutar la aplicación como Administrador.");
        }
    }

    // 14. Verificar Reglas del Firewall
    public static List<FirewallRule> GetFirewallRules()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n=== REGLAS DEL FIREWALL DE WINDOWS (ENTRADA Y SALIDA) ===");
        Console.ResetColor();

        List<FirewallRule> rules = new List<FirewallRule>();

        string psCommand = "Get-NetFirewallRule | Select-Object Name, Group, Direction, Action, Enabled, Profile, LocalAddress, RemoteAddress, Protocol, LocalPort, RemotePort, DisplayApplication | ConvertTo-Json";

        try
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{psCommand}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(startInfo))
            {
                if (process == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error: No se pudo iniciar el proceso de PowerShell para obtener las reglas del firewall.");
                    Console.ResetColor();
                    return rules;
                }

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit(30000);

                if (!string.IsNullOrWhiteSpace(error))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error al ejecutar Get-NetFirewallRule en PowerShell: {error.Trim()}");
                    Console.ResetColor();
                    Console.WriteLine("  Asegúrese de ejecutar la aplicación como Administrador, ya que se requieren permisos elevados para ver las reglas del firewall.");
                }
                else if (!string.IsNullOrWhiteSpace(output))
                {
                    string[] jsonObjects = output.Split(new[] { "}\r\n,{" }, StringSplitOptions.RemoveEmptyEntries)
                                                 .Select(s => s.Trim())
                                                 .ToArray();

                    if (jsonObjects.Length > 0)
                    {
                        jsonObjects[0] = jsonObjects[0].TrimStart('[');
                        jsonObjects[jsonObjects.Length - 1] = jsonObjects[jsonObjects.Length - 1].TrimEnd(']');
                    }

                    foreach (string jsonPart in jsonObjects)
                    {
                        string cleanJsonPart = jsonPart;
                        if (!cleanJsonPart.StartsWith("{")) cleanJsonPart = "{" + cleanJsonPart;
                        if (!cleanJsonPart.EndsWith("}")) cleanJsonPart = cleanJsonPart + "}";

                        FirewallRule rule = new FirewallRule();
                        rule.Name = GetJsonValue(cleanJsonPart, "Name");
                        rule.Group = GetJsonValue(cleanJsonPart, "Group");
                        rule.Direction = GetJsonValue(cleanJsonPart, "Direction");
                        rule.Action = GetJsonValue(cleanJsonPart, "Action");
                        rule.Enabled = GetJsonValue(cleanJsonPart, "Enabled");
                        rule.Profile = GetJsonValue(cleanJsonPart, "Profile");
                        rule.LocalAddress = GetJsonValue(cleanJsonPart, "LocalAddress");
                        rule.RemoteAddress = GetJsonValue(cleanJsonPart, "RemoteAddress");
                        rule.Protocol = GetJsonValue(cleanJsonPart, "Protocol");
                        rule.LocalPort = GetJsonValue(cleanJsonPart, "LocalPort");
                        rule.RemotePort = GetJsonValue(cleanJsonPart, "RemotePort");
                        rule.Application = GetJsonValue(cleanJsonPart, "DisplayApplication");

                        rules.Add(rule);
                    }

                    Console.WriteLine($"Se encontraron {rules.Count} reglas de firewall.");
                    Console.WriteLine("---------------------------------------------");

                    foreach (var rule in rules)
                    {
                        Console.ForegroundColor = rule.Enabled == "True" ? ConsoleColor.Green : ConsoleColor.Yellow;
                        Console.WriteLine($"Nombre: {rule.Name}");
                        Console.ResetColor();
                        Console.WriteLine($"  Grupo: {rule.Group}");
                        Console.WriteLine($"  Dirección: {rule.Direction}");
                        Console.WriteLine($"  Acción: {rule.Action}");
                        Console.WriteLine($"  Habilitada: {rule.Enabled}");
                        Console.WriteLine($"  Perfil: {rule.Profile}");
                        if (!string.IsNullOrEmpty(rule.LocalAddress) && rule.LocalAddress != "Cualquiera/No configurado") Console.WriteLine($"  IP Local: {rule.LocalAddress}");
                        if (!string.IsNullOrEmpty(rule.RemoteAddress) && rule.RemoteAddress != "Cualquiera/No configurado") Console.WriteLine($"  IP Remota: {rule.RemoteAddress}");
                        if (!string.IsNullOrEmpty(rule.Protocol) && rule.Protocol != "Cualquiera/No configurado") Console.WriteLine($"  Protocolo: {rule.Protocol}");
                        if (!string.IsNullOrEmpty(rule.LocalPort) && rule.LocalPort != "Cualquiera/No configurado") Console.WriteLine($"  Puerto Local: {rule.LocalPort}");
                        if (!string.IsNullOrEmpty(rule.RemotePort) && rule.RemotePort != "Cualquiera/No configurado") Console.WriteLine($"  Puerto Remoto: {rule.RemotePort}");
                        if (!string.IsNullOrEmpty(rule.Application) && rule.Application != "Cualquiera/No configurado") Console.WriteLine($"  Aplicación: {rule.Application}");
                        Console.WriteLine("---------------------------------------------");
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("No se encontraron reglas de firewall o la salida de PowerShell estaba vacía.");
                    Console.ResetColor();
                }
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error al obtener las reglas del firewall: {ex.Message}");
            Console.ResetColor();
            Console.WriteLine("  Asegúrese de ejecutar la aplicación como Administrador.");
        }
        return rules;
    }

    private static string GetJsonValue(string json, string key)
    {
        string escapedKey = Regex.Escape(key);
        Match match = Regex.Match(json, $@"""{escapedKey}"":\s*""?(?<value>[^""]*?)""?(,|}})", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            string value = match.Groups["value"].Value.Trim();
            return string.IsNullOrEmpty(value) ? "Cualquiera/No configurado" : value;
        }
        return "N/A";
    }

    // --- FUNCIONES DEL MENÚ ---

    public static void DisplayMenu()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n==============================================");
        Console.WriteLine("        MENÚ DE DIAGNÓSTICO DEL SISTEMA       ");
        Console.WriteLine("==============================================");
        Console.ResetColor();

        Console.WriteLine(" 1. Información del Sistema Operativo");
        Console.WriteLine(" 2. Información del Procesador");
        Console.WriteLine(" 3. Tiempo de Actividad del Sistema");
        Console.WriteLine(" 4. Información de Dominio / Grupo de Trabajo");
        Console.WriteLine(" 5. Estado de la Licencia de Windows");
        Console.WriteLine(" 6. Información de TPM (Trusted Platform Module)");
        Console.WriteLine(" 7. Servicios de Red Esenciales");
        Console.WriteLine(" 8. Adaptadores de Red");
        Console.WriteLine(" 9. Direcciones IP y DNS / Puertas de Enlace");
        Console.WriteLine("10. Verificación de Múltiples Direcciones DNS");
        Console.WriteLine("11. Configuración del Firewall");
        Console.WriteLine("12. Configuración y Servicios de Descubrimiento de Red");
        Console.WriteLine("13. Procesos Escuchando Puertos TCP");
        Console.WriteLine("14. Verificar Reglas del Firewall Windows");
        Console.WriteLine("15. Listar todos los servicios de Windows y su estado");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(" 0. Salir");
        Console.ResetColor();
        Console.WriteLine("----------------------------------------------");
        Console.Write("Por favor, seleccione una opción: ");
    }

    // --- FUNCIÓN PRINCIPAL (MAIN) ---
    public static void Main(string[] args)
    {
        Console.Title = "Herramienta de Diagnóstico del Sistema y Red";

        // Verifica si la aplicación se está ejecutando como administrador
        bool isAdministrator = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        if (!isAdministrator)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ADVERTENCIA: Esta aplicación debe ejecutarse como Administrador para obtener toda la información.");
            Console.WriteLine("Algunas verificaciones pueden fallar o mostrar información incompleta sin privilegios elevados.");
            Console.ResetColor();
            Console.WriteLine("Presione cualquier tecla para continuar de todos modos...");
            Console.ReadKey();
            Console.Clear();
        }

        bool exitApp = false;
        while (!exitApp)
        {
            DisplayMenu();
            string input = Console.ReadLine();
            Console.Clear(); 
            if (int.TryParse(input, out int choice))
            {
                switch (choice)
                {
                    case 1: CheckOperatingSystemInfo(); break;
                    case 2: CheckProcessorInfo(); break;
                    case 3: CheckSystemUptime(); break;
                    case 4: CheckDomainWorkgroupInfo(); break;
                    case 5: CheckWindowsLicenseActivation(); break;
                    case 6: CheckTpmInfo(); break;
                    case 7: CheckEssentialNetworkServices(); break;
                    case 8: CheckNetworkAdapters(); break;
                    case 9: CheckIPAndDNSInfo(); break;
                    case 10: CheckMultipleDNSAddresses(); break;
                    case 11: CheckFirewallProfile(); break;
                    case 12: CheckNetworkDiscovery(); break;
                    case 13: CheckTcpListeningProcesses(); break;
                    case 14: GetFirewallRules(); break;
                    case 15: ListAllServices(); break;
                    case 0:
                        exitApp = true;
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Saliendo de la aplicación. ¡Hasta luego!");
                        Console.ResetColor();
                        break;
                    default:
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Opción no válida. Por favor, ingrese un número del 0 al 13.");
                        Console.ResetColor();
                        break;
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Entrada no válida. Por favor, ingrese un número.");
                Console.ResetColor();
            }

            if (!exitApp)
            {
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("\nPresione cualquier tecla para volver al menú...");
                Console.ResetColor();
                Console.ReadKey();
                Console.Clear(); 
            }
        }
    }
}
