using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace pcapConsoleCsharp
{

    public class LibCapNg
    {
        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngConstruct")]
        public static extern IntPtr MngConstruct([MarshalAs(UnmanagedType.LPStr)] string name_input);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngDispose")]
        public static extern void MngDispose(IntPtr objectToDispose);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngGetVersion", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr MngGetVersion(IntPtr objectToVersion, IntPtr buffer);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngGetFilteredPacketNumber", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int MngGetFilteredPacketNumber(IntPtr objectToFilter);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngParsePcapNG")]
        public static extern int MngParsePcapNG(IntPtr objectToParse, [MarshalAs(UnmanagedType.LPStr)] string ipSrc,
            [MarshalAs(UnmanagedType.LPStr)] string ipDst, int portSrc, int portDst);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngLoad")]
        public static extern bool MngLoad(IntPtr objectToParse);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngGetFirstPacket", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int MngGetFirstPacket(IntPtr objectToVersion, ref IntPtr buffer);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngGetNextPacket", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int MngGetNextPacket(IntPtr objectToVersion, ref IntPtr buffer);
    }

    class Program
    {

        static string getVersion(IntPtr myPcap, IntPtr pStr)
        {
            pStr = LibCapNg.MngGetVersion(myPcap, pStr);
            return (System.Runtime.InteropServices.Marshal.PtrToStringAnsi(pStr));
        }

        static byte[] getFirstPacket(IntPtr myPcap, ref IntPtr pStr) {
            byte[] BSD;
            int size;
            size = LibCapNg.MngGetFirstPacket(myPcap, ref pStr);
            BSD = new byte[size];

            System.Runtime.InteropServices.Marshal.Copy(pStr, BSD, 0, size);
            return BSD;
        }

        static byte[] getNextPacket(IntPtr myPcap, ref IntPtr pStr) {
            byte[] BSD;
            int size;
            size = LibCapNg.MngGetNextPacket(myPcap, ref pStr);
            if (size != 0) {
                BSD = new byte[size];
                System.Runtime.InteropServices.Marshal.Copy(pStr, BSD, 0, size);
            }
            else { BSD = null; }
            return BSD;
        }

        static int Main(string[] args)
        {
            IntPtr myPcap; // pointer on Pcap
            IntPtr pStr; // pointer on char
            byte[] myBSD;

            if (args.Length == 0)
            {
                System.Console.WriteLine("Please enter a file name argument.");
                return 1;
            }
            pStr = IntPtr.Zero; // Initialise pStr to NULL
            myPcap = LibCapNg.MngConstruct(args[0]);
            Console.WriteLine(getVersion(myPcap, pStr));
            if (LibCapNg.MngLoad(myPcap) == false) { return -5; }
            var parsePcapNgReturnCode = (LibCapNg.MngParsePcapNG(myPcap, "10.0.4.7", "10.0.5.4", 20000, 20000));
            if (parsePcapNgReturnCode != 0) { Console.WriteLine("Error during parsing of the pCapNg file"); return parsePcapNgReturnCode; }

            if (LibCapNg.MngGetFilteredPacketNumber(myPcap) != 0) {
                myBSD = getFirstPacket(myPcap, ref pStr);
                for (int cpt = 0; cpt < myBSD.Length; cpt++) { Console.Write("{0:x}", myBSD[cpt]); Console.Write(" "); }
                while (myBSD != null) {
                    myBSD = getNextPacket(myPcap, ref pStr);
                    if (myBSD != null) { Console.WriteLine(); for (int cpt = 0; cpt < myBSD.Length; cpt++) { Console.Write("{0:x}", myBSD[cpt]); Console.Write(" "); }
                        Console.WriteLine("\n--------------------------------------------------------------------------------------"); }
                }
            }
            LibCapNg.MngDispose(myPcap);
            Console.ReadKey();
            return 0;
        }
    }
}
