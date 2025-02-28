using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Collections.Generic;

namespace FrameAnalysis
{
    public static class Program
    {
        private const int FrameDataSize = 1500;
        private const int EthernetIILen = 14;
        private const int MacLen = 6;
        private const int FrametypeLen = 2;
        private const int IpLen = 4;
        private const int IpIndentLen = 12;
        private const int SenderPointerLen = 14;
        private const int TargetPointerLen = 24;
        private const int DscLen = 3;
        private const int SnapLen = 5;
        private const int FcsLen = 4;

        public enum FrameType { IPv4, ARP, DIX, RAW, SNAP, LLC, TOTAL }

        private static readonly Dictionary<FrameType, int> FrameCounter = new()
        {
            { FrameType.ARP, 0 },
            { FrameType.DIX, 0 },
            { FrameType.IPv4, 0 },
            { FrameType.LLC, 0 },
            { FrameType.RAW, 0 },
            { FrameType.SNAP, 0 },
            { FrameType.TOTAL, 0 }
        };

        private static void PrintFramesInfo(byte[] data)
        {
            int pointer = 0;
            while (pointer < data.Length)
            {
                Console.WriteLine($"________________________________________________\nFrame:\t\t\t {++FrameCounter[FrameType.TOTAL]}\t\t\t|");

                // Вывод MAC-адресов
                Console.WriteLine("Target MAC address:\t " + string.Join(':', data[pointer..(pointer + MacLen)].Select(b => b.ToString("X2"))) + "\t|");
                Console.WriteLine("Sender MAC address:\t " + string.Join(':', data[(pointer + MacLen)..(pointer + 2 * MacLen)].Select(b => b.ToString("X2"))) + "\t|");

                // Получаем тип фрейма
                ushort frameLt = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pointer + 2 * MacLen));

                if (FrameDataSize < frameLt)
                {
                    switch (frameLt)
                    {
                        case 0x0800:
                            Console.WriteLine($"Frame type:\t\t {FrameType.IPv4}\t\t\t|");
                            FrameCounter[FrameType.IPv4]++;
                            Console.WriteLine("Sender IP address:\t " + string.Join('.', data[(pointer + 2 * MacLen + FrametypeLen + IpIndentLen)..(pointer + 2 * MacLen + FrametypeLen + IpIndentLen + IpLen)]) + "\t\t|");
                            Console.WriteLine("Target IP address:\t " + string.Join('.', data[(pointer + 2 * MacLen + FrametypeLen + IpIndentLen + IpLen)..(pointer + 2 * MacLen + FrametypeLen + IpIndentLen + 2 * IpLen)]) + "\t\t|");

                            frameLt = (ushort)(IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pointer + 2 * MacLen + FrametypeLen + 2)) + EthernetIILen);
                            Console.WriteLine($"Data size:\t\t {frameLt} bytes\t\t|");
                            pointer += frameLt;
                            break;

                        case 0x0806:
                            Console.WriteLine($"Frame type:\t\t {FrameType.ARP}\t\t\t|");
                            FrameCounter[FrameType.ARP]++;
                            Console.WriteLine("Sender IP address: " + string.Join('.', data[(pointer + 2 * MacLen + FrametypeLen + SenderPointerLen)..(pointer + 2 * MacLen + FrametypeLen + SenderPointerLen + IpLen)]) + "\t\t|");
                            Console.WriteLine("Target IP address: " + string.Join('.', data[(pointer + 2 * MacLen + FrametypeLen + TargetPointerLen)..(pointer + 2 * MacLen + FrametypeLen + TargetPointerLen + IpLen)]) + "\t\t|");

                            pointer += 2 * MacLen + FrametypeLen + SenderPointerLen + EthernetIILen;
                            break;

                        default:
                            Console.WriteLine($"Frame type:\t\t {FrameType.DIX}\t\t\t|");
                            FrameCounter[FrameType.DIX]++;
                            pointer += frameLt + EthernetIILen;
                            break;
                    }
                }
                else
                {
                    ushort frameLlc = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pointer + 2 * MacLen + FrametypeLen));
                    FrameType frameType = frameLlc switch
                    {
                        0xFFFF => FrameType.RAW,
                        0xAAAA => FrameType.SNAP,
                        _ => FrameType.LLC
                    };
                    Console.WriteLine($"Frame type:\t\t {frameType}\t\t\t|");
                    FrameCounter[frameType]++;
                    pointer += frameLt + FrametypeLen + DscLen + SnapLen + FcsLen;
                }
                Console.WriteLine("________________________________________________|");
            }
        }

        private static void PrintFramesCount()
        {
            Console.WriteLine("___________________\nFrame type | Count |\n===========|=======|");
            foreach (var frame in FrameCounter)
                Console.WriteLine($"{frame.Key}\t   | {frame.Value,-5} |");
            Console.WriteLine("___________|_______|\nTotal:\t     " + FrameCounter[FrameType.TOTAL] + "    |\n___________________|");
        }

        public static void Main(string[] args)
        {
            Console.Write("Enter filename: ");
            string filename = Console.ReadLine();
            try
            {
                byte[] data = File.ReadAllBytes(filename);
                PrintFramesInfo(data);
                PrintFramesCount();
                Console.WriteLine($"File Size:   {new FileInfo(filename).Length}  |" );
                Console.WriteLine("___________________|");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: can't open file \"{filename}\"! {ex.Message}");
                Environment.Exit(-1);
            }
        }
    }
}
