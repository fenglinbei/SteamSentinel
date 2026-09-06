using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Independent SDK ABI fixture. CertCreateCertificateContext creates an unassociated
    // in-memory context; this fixture has no CertOpenStore, add-to-store or delete imports.
    // wincrypt.h documents DATE_STAMP Set as a BLOB of FILETIME, unlike the Learn Set
    // table. Only the bounded SDK BLOB is passed: a naked FILETIME could be read as a
    // length/pointer pair and must not be used experimentally in this process.
    private static void TestPhase3CertificateAbi()
    {
        Check("第三批证书ABI DWORD固定4字节且BLOB指针遵循本机对齐",
            Marshal.SizeOf<uint>() == 4 && Marshal.OffsetOf<Phase3AbiBlob>(nameof(Phase3AbiBlob.Data)).ToInt32() == (IntPtr.Size == 8 ? 8 : 4) &&
            Marshal.SizeOf<Phase3AbiBlob>() == (IntPtr.Size == 8 ? 16 : 8));
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=SteamSentinel inert property ABI fixture", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] der = certificate.Export(X509ContentType.Cert);
        X509EnhancedKeyUsageExtension usage = new(new OidCollection { new("1.3.6.1.5.5.7.3.1"), new("1.3.6.1.5.5.7.3.2") }, critical: false);
        byte[] friendly = Encoding.Unicode.GetBytes("Inert ABI friendly name\0"), description = Encoding.Unicode.GetBytes("Inert ABI description\0");
        byte[] stamp = BitConverter.GetBytes(new DateTime(2026, 9, 6, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc());
        (uint Id, string Name, byte[] Value)[] properties =
        [
            (3, "SHA1_HASH", SHA1.HashData(der)),
            (4, "MD5_HASH", MD5.HashData(der)),
            (9, "ENHKEY_USAGE encoded ASN.1", usage.RawData),
            (11, "FRIENDLY_NAME UTF16 including NUL", friendly),
            (13, "DESCRIPTION UTF16 including NUL", description),
            (19, "ARCHIVED non-null empty BLOB", []),
            (20, "KEY_IDENTIFIER bytes", SHA1.HashData(certificate.PublicKey.EncodedKeyValue.RawData)),
            (27, "DATE_STAMP BLOB containing FILETIME", stamp),
            (107, "SHA256_HASH", SHA256.HashData(der))
        ];
        Check("第三批证书ABI Unicode长度以字节计且包含终止NUL、FILETIME为8字节",
            friendly.Length == ("Inert ABI friendly name".Length + 1) * 2 && friendly[^1] == 0 && friendly[^2] == 0 &&
            description.Length == ("Inert ABI description".Length + 1) * 2 && stamp.Length == 8);
        IntPtr context = Phase3AbiCreate(1, der, checked((uint)der.Length));
        if (context == IntPtr.Zero)
        {
            Check($"第三批证书ABI 创建不属于任何存储的公开内存上下文 (Windows error 0x{Marshal.GetLastWin32Error():X8})", false);
            return;
        }
        try
        {
            Phase3AbiContext descriptor = Marshal.PtrToStructure<Phase3AbiContext>(context);
            byte[] copiedDer = new byte[der.Length];
            bool boundedDer = descriptor.Encoded != IntPtr.Zero && descriptor.EncodedBytes == der.Length;
            if (boundedDer) Marshal.Copy(descriptor.Encoded, copiedDer, 0, copiedDer.Length);
            Check("第三批证书ABI 上下文公开DER与本次生成的无害证书相同", boundedDer && copiedDer.AsSpan().SequenceEqual(der));
            foreach ((uint id, string name, byte[] value) in properties)
            {
                IntPtr data = value.Length == 0 ? IntPtr.Zero : Marshal.AllocHGlobal(value.Length);
                IntPtr argument = Marshal.AllocHGlobal(Marshal.SizeOf<Phase3AbiBlob>());
                try
                {
                    if (value.Length > 0) Marshal.Copy(value, 0, data, value.Length);
                    Marshal.StructureToPtr(new Phase3AbiBlob { Bytes = checked((uint)value.Length), Data = data }, argument, false);
                    bool set = Phase3AbiSet(context, id, 0, argument);
                    int setError = Marshal.GetLastWin32Error();
                    uint size = 0;
                    bool sized = set && Phase3AbiGet(context, id, null, ref size);
                    int sizeError = Marshal.GetLastWin32Error();
                    bool equal = false;
                    // A malformed or unexpectedly interpreted returned length never causes
                    // another large allocation. Every expected property is below 1 KiB.
                    if (sized && size == value.Length && size <= 1024)
                    {
                        if (size == 0) equal = true;
                        else
                        {
                            byte[] actual = new byte[checked((int)size)];
                            uint returned = size;
                            equal = Phase3AbiGet(context, id, actual, ref returned) && returned == value.Length && actual.AsSpan().SequenceEqual(value);
                        }
                    }
                    string diagnostic = equal ? "" :
                        $" (Set={set}, SetError=0x{setError:X8}, GetSize={sized}, Size={size}, Expected={value.Length}, GetError=0x{sizeError:X8})";
                    Check("第三批证书ABI " + id + " " + name + " 纯内存Set/Get逐字节往返" + diagnostic, equal);
                }
                finally
                {
                    Marshal.FreeHGlobal(argument);
                    if (data != IntPtr.Zero) Marshal.FreeHGlobal(data);
                }
            }
        }
        finally { Phase3AbiFree(context); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Phase3AbiBlob { public uint Bytes; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Phase3AbiContext
    {
        public uint Encoding; public IntPtr Encoded; public uint EncodedBytes; public IntPtr Info; public IntPtr Store;
    }
    [DllImport("crypt32.dll", EntryPoint = "CertCreateCertificateContext", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr Phase3AbiCreate(uint encoding, byte[] encoded, uint size);
    [DllImport("crypt32.dll", EntryPoint = "CertSetCertificateContextProperty", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Phase3AbiSet(IntPtr context, uint property, uint flags, IntPtr value);
    [DllImport("crypt32.dll", EntryPoint = "CertGetCertificateContextProperty", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Phase3AbiGet(IntPtr context, uint property, [Out] byte[]? value, ref uint size);
    [DllImport("crypt32.dll", EntryPoint = "CertFreeCertificateContext", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Phase3AbiFree(IntPtr context);
}
