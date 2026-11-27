// Real registry/DPAPI/CNG and multi-process fixtures. Built with test-only
// hooks; never compile these hooks into the shipping application.
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Win32;
using Chezhi.Licensing;

internal static class EnrollmentSmoke
{
    private static void Require(bool value,string label) { if(!value) throw new Exception(label); }
    private static void Reject(Action action,string label)
    {
        bool rejected=false;
        try { action(); }
        catch(EnrollmentRecoveryRequired) { rejected=true; }
        catch(CryptographicException) { rejected=true; }
        Require(rejected,label);
    }
    private static Process Start(string mode,Guid id)
    {
        ProcessStartInfo info=new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,
            mode+" "+id.ToString("D"));
        info.UseShellExecute=false;
        return Process.Start(info);
    }
    private static int Finish(Process p)
    {
        using(p)
        {
            if(!p.WaitForExit(30000)) { p.Kill(); p.WaitForExit(); throw new Exception("fixture timeout"); }
            return p.ExitCode;
        }
    }
    private static void Cleanup(DeviceEnrollment e)
    {
        // Test-only cleanup of randomly namespaced fixtures. Do not run this
        // against normal enrollment data or delete user key material.
        try
        {
            Guid slot=e.FixtureSlot();
            string name="CheZhiTech.License.v1."+slot.ToString("N");
            CngProvider provider=CngProvider.MicrosoftSoftwareKeyStorageProvider;
            if(CngKey.Exists(name,provider))
                using(CngKey key=CngKey.Open(name,provider)) key.Delete();
        }
        catch(EnrollmentRecoveryRequired) {}
        Registry.CurrentUser.DeleteSubKeyTree(e.FixturePath,false);
    }

    private static void Run()
    {
        Guid id=Guid.NewGuid();
        DeviceEnrollment e=DeviceEnrollment.Fixture(id);
        try
        {
            Reject(delegate { using(WindowsDeviceKey k=e.OpenExisting()) {} },"missing auto-created");
            using(RegistryKey absent=Registry.CurrentUser.OpenSubKey(e.FixturePath))
                Require(absent==null,"missing open wrote registry");
            Process a=Start("create",id), b=Start("create",id);
            int x=Finish(a),y=Finish(b);
            Require((x==0&&y==20)||(x==20&&y==0),"concurrent enrollment not exclusive");
            byte[] fingerprint;
            using(WindowsDeviceKey key=e.OpenExisting()) fingerprint=key.Fingerprint;
            Require(Finish(Start("open",id))==0,"cross-process reopen");
            using(WindowsDeviceKey key=e.OpenExisting())
                Require(Convert.ToBase64String(key.Fingerprint)==Convert.ToBase64String(fingerprint),"fingerprint changed");
            using(RegistryKey k=Registry.CurrentUser.OpenSubKey(e.FixturePath,true))
            {
                byte[] original=(byte[])k.GetValue("Enrollment");
                Require(original.Length>56,"metadata not protected");
                try
                {
                    byte[] corrupt=(byte[])original.Clone();corrupt[corrupt.Length/2]^=1;
                    k.SetValue("Enrollment",corrupt,RegistryValueKind.Binary);k.Flush();
                    Reject(delegate { using(WindowsDeviceKey key=e.OpenExisting()) {} },"corrupt record accepted");
                    Reject(delegate { using(WindowsDeviceKey key=e.EnrollFirst(DeviceKeyPolicy.Software)) {} },"corrupt record overwritten");
                }
                finally {k.SetValue("Enrollment",original,RegistryValueKind.Binary);k.Flush();}
            }
            Guid slot=e.FixtureSlot();
            string name="CheZhiTech.License.v1."+slot.ToString("N");
            using(CngKey key=CngKey.Open(name,CngProvider.MicrosoftSoftwareKeyStorageProvider)) key.Delete();
            Reject(delegate { using(WindowsDeviceKey key=e.OpenExisting()) {} },"missing CNG key accepted");
            Reject(delegate { using(WindowsDeviceKey key=e.EnrollFirst(DeviceKeyPolicy.Software)) {} },"missing CNG key replaced");
            Require(!CngKey.Exists(name,CngProvider.MicrosoftSoftwareKeyStorageProvider),"missing key recreated");
        }
        finally {Cleanup(e);}
        foreach(int stage in new[]{1,2})
        {
            Guid pending=Guid.NewGuid();
            DeviceEnrollment f=DeviceEnrollment.Fixture(pending);
            try
            {
                Require(Finish(Start("crash"+stage,pending))==71,"fault hook did not terminate process");
                Guid slot=f.FixtureSlot();
                string name="CheZhiTech.License.v1."+slot.ToString("N");
                Require(CngKey.Exists(name,CngProvider.MicrosoftSoftwareKeyStorageProvider)==(stage==2),"unexpected crash-stage key existence");
                Reject(delegate { using(WindowsDeviceKey key=f.OpenExisting()) {} },"pending open accepted");
                Reject(delegate { using(WindowsDeviceKey key=f.EnrollFirst(DeviceKeyPolicy.Software)) {} },"pending overwritten");
                Require(f.FixtureSlot()==slot,"pending slot changed");
            }
            finally {Cleanup(f);}
        }
        Console.WriteLine("PASS registry DPAPI enrollment intent, concurrent create, cross-process reopen, tamper/missing-key denial and two process-crash boundaries");
    }

    private static int Main(string[] args)
    {
        try
        {
            if(args.Length==0) {Run();return 0;}
            if(args.Length!=2) return 2;
            DeviceEnrollment e=DeviceEnrollment.Fixture(new Guid(args[1]));
            if(args[0]=="open") {using(WindowsDeviceKey key=e.OpenExisting()) {} return 0;}
            if(args[0]=="crash1") e.FaultHook=delegate(int n){if(n==1) Environment.Exit(71);};
            else if(args[0]=="crash2") e.FaultHook=delegate(int n){if(n==2) Environment.Exit(71);};
            else if(args[0]!="create") return 3;
            using(WindowsDeviceKey key=e.EnrollFirst(DeviceKeyPolicy.Software)) {}
            return 0;
        }
        catch(EnrollmentRecoveryRequired) {return 20;}
        catch(Exception ex) {Console.Error.WriteLine(ex.GetType().Name+": "+ex.Message);return 5;}
    }
}
