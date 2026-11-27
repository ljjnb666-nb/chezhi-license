// Test-only actual .NET -> Go DLL -> CNG -> loopback HTTPS exchange.
// Fixture card and public trust values are not production credentials.
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Chezhi.Licensing;

internal static class OnlineSmoke
{
    private static byte[] Hex(string s)
    {
        byte[] b=new byte[s.Length/2];
        for(int i=0;i<b.Length;i++) b[i]=Convert.ToByte(s.Substring(i*2,2),16);
        return b;
    }
    private static void Check(bool x,string label) {if(!x) throw new Exception(label);}
    private static bool Result(Task<bool> t)
    {
        Check(t!=null && t.Wait(30000),"async request timeout or rejected");
        return t.Result;
    }
    private static int Main(string[] args)
    {
        try
        {
            if(args.Length!=3) return 2;
            string[] cfg=File.ReadAllLines(args[0]);
            byte[] hash=Hex(args[2]),scope=Hex(cfg[1]),pub=Hex(cfg[2]);
            byte[] card=Encoding.ASCII.GetBytes("ABCDE-FGHJK-MNPQR-STVWX-YZ012");
            byte[] badHash=(byte[])hash.Clone();badHash[0]^=1;
            bool rejected=false;
            try {new NativeLicenseClient(args[1],badHash,cfg[0],scope,pub);}
            catch(CryptographicException) {rejected=true;}
            Check(rejected,"bad DLL digest accepted");
            NativeLicenseClient client=new NativeLicenseClient(args[1],hash,cfg[0],scope,pub);
            Guid slot=Guid.NewGuid();
            string name="CheZhiTech.License.v1."+slot.ToString("N");
            try
            {
                using(WindowsDeviceKey key=WindowsDeviceKey.Enroll(slot,DeviceKeyPolicy.Software))
                {
                    LicenseMetadata meta;
                    Check(client.Authorize(LicenseOperation.Activate,card,key,out meta)==LicenseStatus.Ok && meta!=null,"native activation");
                    byte[] fingerprint=key.Fingerprint;
                    using(WindowsDeviceKey reopened=WindowsDeviceKey.Open(slot,DeviceKeyPolicy.Software,fingerprint))
                    using(LicenseCoordinator coordinator=new LicenseCoordinator(client,reopened,card))
                    {
                        Check(Result(coordinator.VerifyAsync(LicenseOperation.Validate)) && coordinator.CanStartProtectedOperation,"native validate");
                        coordinator.NetworkChanged(false);
                        Check(!coordinator.CanStartProtectedOperation && coordinator.VerifyAsync(LicenseOperation.Renew)==null,"offline grant");
                        coordinator.NetworkChanged(true);
                        Check(!coordinator.CanStartProtectedOperation,"network recovery grant");
                        Check(Result(coordinator.VerifyAsync(LicenseOperation.Renew)),"native renew");
                        coordinator.Dispose();
                        Check(!coordinator.CanStartProtectedOperation && coordinator.VerifyAsync(LicenseOperation.Validate)==null,"closed coordinator");
                    }
                    byte[] wrong=(byte[])pub.Clone();wrong[0]^=1;
                    NativeLicenseClient bad=new NativeLicenseClient(args[1],hash,cfg[0],scope,wrong);
                    Check(bad.Authorize(LicenseOperation.Validate,card,key,out meta)==LicenseStatus.UntrustedResponse && meta==null,"wrong trust key");
                    byte[] denied=Encoding.ASCII.GetBytes("DENIED-FIXTURE");
                    Check(client.Authorize(LicenseOperation.Validate,denied,key,out meta)==LicenseStatus.Denied && meta==null,"denied response");
                    byte[] wrongNonce=Encoding.ASCII.GetBytes("NONCE-FIXTURE");
                    Check(client.Authorize(LicenseOperation.Validate,wrongNonce,key,out meta)==LicenseStatus.UntrustedResponse && meta==null,"signed wrong nonce");
                }
            }
            finally
            {
                CngProvider provider=CngProvider.MicrosoftSoftwareKeyStorageProvider;
                if(CngKey.Exists(name,provider)) using(CngKey key=CngKey.Open(name,provider)) key.Delete();
                Array.Clear(card,0,card.Length);
            }
            Console.WriteLine("PASS Windows native online interop: verified DLL, CNG proof, TLS, activate/validate/renew, denial, wrong trust and wrong nonce, coordinator");
            return 0;
        }
        catch(Exception ex) {Console.Error.WriteLine(ex.GetType().Name+": "+ex.Message);return 1;}
    }
}
