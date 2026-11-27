// CI uses disposable random per-user software KSP names only. No production
// device identity, card, TPM requirement or arbitrary key deletion.
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Chezhi.Licensing;

internal static class DeviceKeySmoke
{
    private static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }
    private static byte[] Parse(string s)
    {
        if (s.Length != 64) throw new ArgumentException("fingerprint");
        byte[] b = new byte[32];
        for (int i=0;i<b.Length;i++) b[i] = Convert.ToByte(s.Substring(i*2,2),16);
        return b;
    }
    private static void Require(bool ok, string label) { if (!ok) throw new Exception(label); }
    private static void Reject(Action action, string label)
    {
        bool rejected=false;
        try { action(); }
        catch (CryptographicException) { rejected=true; }
        catch (ArgumentException) { rejected=true; }
        Require(rejected,label);
    }
    private static string Name(Guid slot) { return "CheZhiTech.License.v1."+slot.ToString("N"); }

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length<2) return 1;
            Guid slot = new Guid(args[1]);
            if (slot==Guid.Empty) return 2;
            CngProvider provider=CngProvider.MicrosoftSoftwareKeyStorageProvider;
            if (args[0]=="create")
            {
                Require(!CngKey.Exists(Name(slot),provider),"fixture collision");
                using (WindowsDeviceKey key=WindowsDeviceKey.Enroll(slot,DeviceKeyPolicy.Software))
                    Console.WriteLine(Hex(key.Fingerprint));
                return 0;
            }
            if (args[0]=="cleanup")
            {
                // Only an explicitly created disposable fixture, pinned to
                // the expected public fingerprint, may be removed.
                if (args.Length!=3) return 3;
                using (WindowsDeviceKey check=WindowsDeviceKey.Open(slot,DeviceKeyPolicy.Software,Parse(args[2]))) {}
                using (CngKey key=CngKey.Open(Name(slot),provider)) key.Delete();
                Require(!CngKey.Exists(Name(slot),provider),"fixture cleanup");
                return 0;
            }
            if (args[0]!="reopen" || args.Length!=3) return 4;
            byte[] expected=Parse(args[2]);
            using (WindowsDeviceKey key=WindowsDeviceKey.Open(slot,DeviceKeyPolicy.Software,expected))
            {
                Require(Hex(key.Fingerprint)==args[2],"identity changed");
                byte[] point=key.PublicPoint;
                byte[] blob=new byte[72];
                blob[0]=0x45;blob[1]=0x43;blob[2]=0x53;blob[3]=0x31;blob[4]=32;
                Buffer.BlockCopy(point,1,blob,8,64);
                byte[] digest;
                using (SHA256 hash=SHA256.Create()) digest=hash.ComputeHash(new byte[]{1,2,3});
                using (CngKey pub=CngKey.Import(blob,CngKeyBlobFormat.EccPublicBlob))
                using (ECDsaCng verify=new ECDsaCng(pub))
                {
                    Require(verify.VerifyHash(digest,key.SignDigest(digest)),"reopened signature");
                    IntPtr d=Marshal.AllocHGlobal(32);
                    IntPtr s=Marshal.AllocHGlobal(64);
                    try
                    {
                        Marshal.Copy(digest,0,d,32);
                        Require(key.SignCallback(IntPtr.Zero,d,s)==0,"callback status");
                        byte[] sig=new byte[64];Marshal.Copy(s,sig,0,64);
                        Require(verify.VerifyHash(digest,sig),"callback signature");
                        key.Dispose();
                        Require(key.SignCallback(IntPtr.Zero,d,s)!=0,"disposed callback accepted");
                        Marshal.Copy(s,sig,0,64);
                        foreach(byte b in sig) Require(b==0,"failure output not zero");
                    }
                    finally {Marshal.FreeHGlobal(s);Marshal.FreeHGlobal(d);}
                }
            }
            using (CngKey key=CngKey.Open(Name(slot),provider))
            {
                Require(key.ExportPolicy==CngExportPolicies.None,"export policy");
                Reject(delegate { key.Export(CngKeyBlobFormat.EccPrivateBlob); },"private export accepted");
            }
            byte[] wrong=(byte[])expected.Clone();wrong[0]^=1;
            Reject(delegate { using (WindowsDeviceKey key=WindowsDeviceKey.Open(slot,DeviceKeyPolicy.Software,wrong)) {} },"wrong fingerprint accepted");
            Reject(delegate { using (WindowsDeviceKey key=WindowsDeviceKey.Enroll(slot,DeviceKeyPolicy.Software)) {} },"duplicate enrollment overwrote");
            Guid missing=Guid.NewGuid();
            Reject(delegate { using (WindowsDeviceKey key=WindowsDeviceKey.Open(missing,DeviceKeyPolicy.Software,expected)) {} },"missing key recreated");
            Require(!CngKey.Exists(Name(missing),provider),"missing key side effect");
            // A TPM-required open must never fall back to the software slot.
            Reject(delegate { using (WindowsDeviceKey key=WindowsDeviceKey.Open(slot,DeviceKeyPolicy.TpmRequired,expected)) {} },"silent TPM fallback");
            using (WindowsDeviceKey key=WindowsDeviceKey.Open(slot,DeviceKeyPolicy.Software,expected)) {}
            Console.WriteLine("PASS Windows per-user CNG cross-process reopen, signature callback, nonexport policy, duplicate/missing/mismatch and no TPM fallback");
            return 0;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("DeviceKeySmoke failed: "+e.GetType().Name+" / "+e.Message);
            return 5;
        }
    }
}
