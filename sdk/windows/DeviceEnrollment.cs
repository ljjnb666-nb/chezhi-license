// P4.2: durable, current-user enrollment intent and pinned identity.
// Registry stores only DPAPI-protected public metadata, not a private key.
// Explicit enrollment is not a recovery mechanism.
using System;
using System.IO;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace Chezhi.Licensing
{
    internal sealed class EnrollmentRecoveryRequired : InvalidOperationException
    {
        internal EnrollmentRecoveryRequired() : base("Device identity needs explicit recovery.") {}
    }

    internal sealed class DeviceEnrollment
    {
        private const string BasePath = @"Software\CheZhiTech\LicenseIdentity\v1";
        private const string ValueName = "Enrollment";
        private const int RecordSize = 56;
        private readonly string path;
        private readonly string mutexName;
        private readonly byte[] entropy;
        private readonly SecurityIdentifier user;
        private static readonly SecurityIdentifier SystemSid =
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        internal DeviceEnrollment() : this(BasePath) {}
        private DeviceEnrollment(string registryPath)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) user = identity.User;
            if (user == null) throw new SecurityException("Windows user identity unavailable.");
            path = registryPath;
            entropy = Encoding.UTF8.GetBytes("CheZhiTech.DeviceEnrollment.v1|" + user.Value + "|" + path);
            using (SHA256 hash = SHA256.Create())
                mutexName = @"Global\CheZhiTech.Enrollment." + BitConverter.ToString(hash.ComputeHash(entropy)).Replace("-", "");
        }

#if CHEZHI_SDK_TEST
        // Test-only isolated profile and fault hook are absent in production.
        internal static DeviceEnrollment Fixture(Guid id)
        {
            if (id == Guid.Empty) throw new ArgumentException("fixture id");
            return new DeviceEnrollment(BasePath + @"-Fixtures\" + id.ToString("N"));
        }
        internal string FixturePath { get { return path; } }
        internal Action<int> FaultHook;
        internal Guid FixtureSlot()
        {
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(path))
                return Read(k).Slot;
        }
#endif

        private sealed class Record
        {
            internal Guid Slot;
            internal DeviceKeyPolicy Policy;
            internal byte[] Fingerprint;
            internal bool Ready;
        }

        private static bool AllZero(byte[] bytes)
        {
            int n = 0;
            foreach (byte b in bytes) n |= b;
            return n == 0;
        }

        private static bool ValidPolicy(DeviceKeyPolicy policy)
        {
            return policy == DeviceKeyPolicy.Software || policy == DeviceKeyPolicy.TpmRequired;
        }

        private byte[] Encode(Record r)
        {
            byte[] b = new byte[RecordSize];
            b[0]=0x43; b[1]=0x5A; b[2]=0x45; b[3]=0x31; // CZE1
            b[4]=(byte)(r.Ready ? 2 : 1); b[5]=(byte)r.Policy;
            Buffer.BlockCopy(r.Slot.ToByteArray(),0,b,8,16);
            Buffer.BlockCopy(r.Fingerprint,0,b,24,32);
            return b;
        }

        private Record Decode(byte[] b)
        {
            if (b.Length != RecordSize || b[0]!=0x43 || b[1]!=0x5A || b[2]!=0x45 || b[3]!=0x31 ||
                (b[4]!=1 && b[4]!=2) || b[6]!=0 || b[7]!=0) throw new EnrollmentRecoveryRequired();
            byte[] guid = new byte[16], fp = new byte[32];
            Buffer.BlockCopy(b,8,guid,0,16);
            Buffer.BlockCopy(b,24,fp,0,32);
            Record r = new Record { Slot=new Guid(guid), Policy=(DeviceKeyPolicy)b[5], Fingerprint=fp, Ready=b[4]==2 };
            if (r.Slot==Guid.Empty || !ValidPolicy(r.Policy) || r.Ready==AllZero(fp))
                throw new EnrollmentRecoveryRequired();
            return r;
        }

        private RegistrySecurity PrivateRegistrySecurity()
        {
            RegistrySecurity s = new RegistrySecurity();
            s.SetOwner(user);
            s.SetAccessRuleProtection(true,false);
            foreach (SecurityIdentifier sid in new[] { user, SystemSid })
                s.AddAccessRule(new RegistryAccessRule(sid, RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            return s;
        }

        private MutexSecurity PrivateMutexSecurity()
        {
            MutexSecurity s = new MutexSecurity();
            s.SetOwner(user);
            s.SetAccessRuleProtection(true,false);
            foreach (SecurityIdentifier sid in new[] { user, SystemSid })
                s.AddAccessRule(new MutexAccessRule(sid, MutexRights.FullControl, AccessControlType.Allow));
            return s;
        }

        // Existing objects are never silently re-ACL'd. Refuse an unexpected
        // owner, inherited DACL or grants to other principals. Administrators
        // and hostile same-user code are outside this boundary.
        private void VerifySecurity(ObjectSecurity s)
        {
            if (!user.Equals(s.GetOwner(typeof(SecurityIdentifier))) || !s.AreAccessRulesProtected)
                throw new SecurityException("Enrollment object ACL mismatch.");
            AuthorizationRuleCollection rules = ((CommonObjectSecurity)s).GetAccessRules(true,true,typeof(SecurityIdentifier));
            foreach (AuthorizationRule rule in rules)
            {
                AccessRule access = rule as AccessRule;
                if (access == null || access.IsInherited ||
                    (!user.Equals(access.IdentityReference) && !SystemSid.Equals(access.IdentityReference)))
                    throw new SecurityException("Unexpected enrollment object access rule.");
            }
        }

        private Record Read(RegistryKey k)
        {
            if (k == null) throw new EnrollmentRecoveryRequired();
            VerifySecurity(k.GetAccessControl());
            object value = k.GetValue(ValueName,null,RegistryValueOptions.DoNotExpandEnvironmentNames);
            byte[] cipher = value as byte[];
            if (cipher == null || cipher.Length == 0 || cipher.Length > 4096 ||
                k.GetValueKind(ValueName)!=RegistryValueKind.Binary)
                throw new EnrollmentRecoveryRequired();
            byte[] raw;
            try { raw=ProtectedData.Unprotect(cipher,entropy,DataProtectionScope.CurrentUser); }
            catch (CryptographicException) { throw new EnrollmentRecoveryRequired(); }
            try { return Decode(raw); }
            finally { Array.Clear(raw,0,raw.Length); }
        }

        private void Write(RegistryKey k, Record r)
        {
            VerifySecurity(k.GetAccessControl());
            byte[] raw=Encode(r);
            byte[] cipher;
            try { cipher=ProtectedData.Protect(raw,entropy,DataProtectionScope.CurrentUser); }
            finally { Array.Clear(raw,0,raw.Length); }
            // Single registry value replacement; flush the pending intent
            // before creating a key, and ready metadata before returning it.
            k.SetValue(ValueName,cipher,RegistryValueKind.Binary);
            k.Flush();
            Record confirmed=Read(k);
            if (confirmed.Slot!=r.Slot || confirmed.Policy!=r.Policy || confirmed.Ready!=r.Ready)
                throw new EnrollmentRecoveryRequired();
            int diff=0;
            for(int i=0;i<32;i++) diff |= confirmed.Fingerprint[i]^r.Fingerprint[i];
            if(diff!=0) throw new EnrollmentRecoveryRequired();
        }

        private T WithLease<T>(Func<bool,T> action)
        {
            bool created,held=false,abandoned=false;
            using (Mutex mutex=new Mutex(false,mutexName,out created,PrivateMutexSecurity()))
            {
                VerifySecurity(mutex.GetAccessControl());
                try
                {
                    try { held=mutex.WaitOne(TimeSpan.FromSeconds(10)); }
                    catch (AbandonedMutexException) { held=true; abandoned=true; }
                    if (!held) throw new IOException("Device enrollment is busy.");
                    return action(abandoned);
                }
                finally { if (held) mutex.ReleaseMutex(); }
            }
        }

        // Only an explicitly requested first enrollment may call this.
        // A preexisting key or empty/corrupt/pending record is NOT repaired.
        // An interrupted enrollment is retained for operator reconciliation.
        internal WindowsDeviceKey EnrollFirst(DeviceKeyPolicy policy)
        {
            if (!ValidPolicy(policy)) throw new ArgumentOutOfRangeException("policy");
            return WithLease(delegate(bool abandoned)
            {
                if (abandoned) throw new EnrollmentRecoveryRequired();
                using (RegistryKey existing=Registry.CurrentUser.OpenSubKey(path))
                    if (existing!=null) throw new EnrollmentRecoveryRequired();

                using (RegistryKey k=Registry.CurrentUser.CreateSubKey(path,RegistryKeyPermissionCheck.ReadWriteSubTree,PrivateRegistrySecurity()))
                {
                    if (k==null) throw new IOException("Cannot create enrollment record.");
                    VerifySecurity(k.GetAccessControl());
                    // Existing unexpected values must not be overwritten.
                    if(k.ValueCount!=0 || k.SubKeyCount!=0) throw new EnrollmentRecoveryRequired();
                    Record r=new Record { Slot=Guid.NewGuid(), Policy=policy, Fingerprint=new byte[32] };
                    Write(k,r);
#if CHEZHI_SDK_TEST
                    if(FaultHook!=null) FaultHook(1);
#endif
                    WindowsDeviceKey device=WindowsDeviceKey.Enroll(r.Slot,policy);
                    try
                    {
#if CHEZHI_SDK_TEST
                        if(FaultHook!=null) FaultHook(2);
#endif
                        r.Fingerprint=device.Fingerprint; r.Ready=true;
                        Write(k,r);
                        return device;
                    }
                    catch { device.Dispose(); throw; }
                }
            });
        }

        // Normal startup has no creation path, even if the record/key is
        // missing or a prior enrollment was interrupted.
        internal WindowsDeviceKey OpenExisting()
        {
            return WithLease(delegate(bool abandoned)
            {
                using (RegistryKey k=Registry.CurrentUser.OpenSubKey(path))
                {
                    Record r=Read(k);
                    if (!r.Ready) throw new EnrollmentRecoveryRequired();
                    return WindowsDeviceKey.Open(r.Slot,r.Policy,r.Fingerprint);
                }
            });
        }
    }
}
