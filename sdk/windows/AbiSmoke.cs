// .NET Framework v4 csc-compatible ABI smoke test. No real cards or secrets.
using System;
using System.Runtime.InteropServices;
internal static class AbiSmoke
{
    [DllImport("chezhi_license_sdk.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern UInt32 ChezhiLicenseABIVersion();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate Int32 SignCallback(IntPtr context, IntPtr digest, IntPtr signature);

    [DllImport("chezhi_license_sdk.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern Int32 ChezhiLicenseAuthorize(
        IntPtr origin, UInt32 originLen, IntPtr deployment, IntPtr trusted,
        IntPtr card, UInt32 cardLen, IntPtr device, SignCallback signer,
        IntPtr context, UInt32 operation, [In, Out] byte[] output, UInt32 outputLen);

    private static int Main()
    {
        if (IntPtr.Size != 8 || ChezhiLicenseABIVersion() != 1) return 1;
        byte[] result = new byte[32];
        for (int i=0;i<result.Length;i++) result[i]=0xA5;
        int status=ChezhiLicenseAuthorize(IntPtr.Zero,0,IntPtr.Zero,IntPtr.Zero,
            IntPtr.Zero,0,IntPtr.Zero,null,IntPtr.Zero,1,result,32);
        if (status != 1) return 2;
        foreach (byte b in result) if (b != 0) return 3;
        Console.WriteLine("PASS Windows x64 .NET Framework native ABI version, invalid input and output clearing");
        return 0;
    }
}
