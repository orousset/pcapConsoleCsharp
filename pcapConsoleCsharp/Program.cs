using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using FSFB2_structure;

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
            [MarshalAs(UnmanagedType.LPStr)] string ipDst, int portSrc, int portDst, int srcNodeID, int dstNodeID);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngLoad")]
        public static extern bool MngLoad(IntPtr objectToParse);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngGetTimeStamp")]
        public static extern double MngGetTimeStamp(IntPtr objectToParse);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngGetFirstPacket", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int MngGetFirstPacket(IntPtr objectToVersion, ref IntPtr buffer);

        [DllImport("LibPcapNgDLL.dll", EntryPoint = "MngGetNextPacket", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int MngGetNextPacket(IntPtr objectToVersion, ref IntPtr buffer);
    }

    class Program
    {
        static string getVersion(IntPtr myPcap, IntPtr pStr) {
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

        static double getTimeStamp(IntPtr myPcap) {
            return LibCapNg.MngGetTimeStamp(myPcap);
        }

        static int Main(string[] args)
        {
            IntPtr myPcap; // pointer on Pcap
            IntPtr pStr; // pointer on char
            byte[] myBSD;
            const int BSD_offset = 0x4E; // Offset to the BSD start (from the start of the IP Packet)
            const int DstID_offset = 0x3E; // Offset to the dest_ID (from the start of the IP Packet)
            int[] bitMask = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

            string variable = "MEF_06_T";

            if (args.Length < 3)
            {
                System.Console.WriteLine(@"The arguments shall be [1] '*.pcapng' [2] the name of the host and [3] the name of the SIO");
                return 1;
            }
            FSFB2Node myFSFB2Node = new FSFB2Node();
            FSFB2DataFlow myFSFB2_DataFlow = new FSFB2DataFlow();
            myFSFB2Node.NameHost = args[1];
            if (myFSFB2Node.InitListNotes() != ERRORS.NO_ERROR) { string[] listOfNodes = myFSFB2Node.getListNodes(); }
            if (myFSFB2_DataFlow.InitFSFB2DataFlow(args[2], myFSFB2Node) == ERRORS.NO_ERROR) {
                Console.WriteLine("FSFB2 data structure initialised");
            } else {
                Console.WriteLine("Error encountered while attempting to initialised {0} FSFB2 data structure", myFSFB2Node.NameHost);
                return -1;
            }

            pStr = IntPtr.Zero; // Initialise pStr to NULL
            myPcap = LibCapNg.MngConstruct(args[0]);
            Console.WriteLine("Version of the LibPcapNGDLL is {0}", getVersion(myPcap, pStr));
            if (LibCapNg.MngLoad(myPcap) == false) { return -5; }
            var parsePcapNgReturnCode = (LibCapNg.MngParsePcapNG(myPcap, myFSFB2_DataFlow.IPAddressRed, "*", 20000, 20000, 0, 0));
            if (parsePcapNgReturnCode != 0) { Console.WriteLine("Error during parsing of the pCapNg file"); return parsePcapNgReturnCode; }

            if (LibCapNg.MngGetFilteredPacketNumber(myPcap) != 0) {
                int offset = myFSFB2_DataFlow.GetIndex(variable, "RX");
                int BitOffset = offset % 8;
                int ByteOffset = (int) offset / 8;
                string DstNodeID_BCtmp = Convert.ToString((UInt16) (0-myFSFB2_DataFlow.Subnet), 16); // Compute the subnet
                string DstNodeID_BC = DstNodeID_BCtmp.Substring(2) + DstNodeID_BCtmp.Substring(0, 2); // Change it to correct endianness

                myBSD = getFirstPacket(myPcap, ref pStr);
                string DstNodeID_BSD = Convert.ToString(myBSD[DstID_offset], 16) + Convert.ToString(myBSD[DstID_offset + 1], 16);

                if (DstNodeID_BSD == DstNodeID_BC) {
                    Console.WriteLine("{0} - {1} : {2}", getTimeStamp(myPcap), variable, myBSD[BSD_offset + ByteOffset] & bitMask[BitOffset]);
                }
                while (myBSD != null) {
                    myBSD = getNextPacket(myPcap, ref pStr);
                    if (myBSD != null) {
                        DstNodeID_BSD = Convert.ToString(myBSD[DstID_offset], 16) + Convert.ToString(myBSD[DstID_offset + 1], 16);
                        if (DstNodeID_BSD == DstNodeID_BC) {
                            Console.WriteLine("{0} - {1} : {2}", getTimeStamp(myPcap), variable, myBSD[BSD_offset + ByteOffset] & bitMask[BitOffset]);
                        }
                    }
                }
            } else { Console.WriteLine("No packet detected"); }
            LibCapNg.MngDispose(myPcap);
            Console.ReadKey();
            return 0;
        }
    }
}
