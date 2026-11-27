// P4.2 candidate: explicit per-user CNG enrollment and pinned reopen.
// Compatible with the existing .NET Framework 4.x compiler. No private
// key serialization, silent provider fallback, or automatic key replacement.
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace Chezhi.Licensing
{
    internal enum DeviceKeyPolicy { Software = 1, TpmRequired = 2 }

    internal sealed class WindowsDeviceKey : IDisposable
    {
        private readonly object gate = new object();
        private CngKey key;
        private ECDsaCng signer;
        private readonly byte[] point;
        private readonly byte[] fingerprint;

        private static CngProvider Provider(DeviceKeyPolicy policy)
        {
            switch (policy)
            {
                case DeviceKeyPolicy.Software: return CngProvider.MicrosoftSoftwareKeyStorageProvider;
                case DeviceKeyPolicy.TpmRequired: return new CngProvider("Microsoft Platform Crypto Provider");
                default: throw new ArgumentOutOfRangeException("policy");
            }
        }

        // A random slot is chosen and recorded by the enrollment coordinator.
        // Never accept arbitrary filesystem paths or externally supplied names.
        private static string Name(Guid slot)
        {
            if (slot == Guid.Empty) throw new ArgumentException("Invalid enrollment slot.");
            return "CheZhiTech.License.v1." + slot.ToString("N");
        }

        private WindowsDeviceKey(CngKey opened, CngProvider provider, string name, byte[] expected)
        {
            if (opened.IsEphemeral || opened.IsMachineKey ||
                !String.Equals(opened.KeyName, name, StringComparison.Ordinal) ||
                !String.Equals(opened.Provider.Provider, provider.Provider, StringComparison.Ordinal) ||
                !String.Equals(opened.Algorithm.Algorithm, CngAlgorithm.ECDsaP256.Algorithm, StringComparison.Ordinal) ||
                opened.KeySize != 256 || opened.ExportPolicy != CngExportPolicies.None ||
                opened.KeyUsage != CngKeyUsages.Signing)
                throw new CryptographicException("Device key policy mismatch.");

            byte[] blob = opened.Export(CngKeyBlobFormat.EccPublicBlob);
            // BCRYPT_ECCKEY_BLOB: little-endian ECS1 magic and cbKey=32,
            // then two unsigned 32-byte big-endian coordinates.
            if (blob.Length != 72 || blob[0] != 0x45 || blob[1] != 0x43 ||
                blob[2] != 0x53 || blob[3] != 0x31 ||
                blob[4] != 32 || blob[5] != 0 || blob[6] != 0 || blob[7] != 0)
                throw new CryptographicException("Invalid device public point.");
            point = new byte[65];
            point[0] = 4;
            Buffer.BlockCopy(blob, 8, point, 1, 64);
            using (SHA256 hash = SHA256.Create()) fingerprint = hash.ComputeHash(point);
            if (expected != null && !Equal(fingerprint, expected))
                throw new CryptographicException("Device identity changed; explicit recovery required.");
            signer = new ECDsaCng(opened);
            key = opened;
        }

        // Enrollment and reopening are intentionally different operations.
        // Create never passes OverwriteExistingKey. A duplicate or provider
        // error is returned to the coordinator, not converted into a retry
        // with another provider or a new identity.
        internal static WindowsDeviceKey Enroll(Guid slot, DeviceKeyPolicy policy)
        {
            string name = Name(slot);
            CngProvider provider = Provider(policy);
            CngKeyCreationParameters options = new CngKeyCreationParameters();
            options.Provider = provider;
            options.KeyCreationOptions = CngKeyCreationOptions.None;
            options.ExportPolicy = CngExportPolicies.None;
            options.KeyUsage = CngKeyUsages.Signing;
            CngKey created = CngKey.Create(CngAlgorithm.ECDsaP256, name, options);
            try { return new WindowsDeviceKey(created, provider, name, null); }
            catch
            {
                // Do not delete or replace a persisted key on a validation
                // error. The enrollment coordinator must reconcile it.
                created.Dispose();
                throw;
            }
        }

        internal static WindowsDeviceKey Open(Guid slot, DeviceKeyPolicy policy, byte[] expectedFingerprint)
        {
            if (expectedFingerprint == null || expectedFingerprint.Length != 32)
                throw new ArgumentException("A pinned device fingerprint is required.");
            byte[] expected = (byte[])expectedFingerprint.Clone();
            string name = Name(slot);
            CngProvider provider = Provider(policy);
            CngKey opened = CngKey.Open(name, provider, CngKeyOpenOptions.None);
            try { return new WindowsDeviceKey(opened, provider, name, expected); }
            catch { opened.Dispose(); throw; }
        }

        private static bool Equal(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        internal byte[] PublicPoint { get { return (byte[])point.Clone(); } }
        internal byte[] Fingerprint { get { return (byte[])fingerprint.Clone(); } }

        internal byte[] SignDigest(byte[] digest)
        {
            if (digest == null || digest.Length != 32) throw new ArgumentException("Expected SHA-256 digest.");
            lock (gate)
            {
                if (signer == null) throw new ObjectDisposedException("WindowsDeviceKey");
                byte[] signature = signer.SignHash(digest);
                if (signature == null || signature.Length != 64)
                    throw new CryptographicException("Unexpected P-256 signature format.");
                return signature;
            }
        }

        // Must stay alive until the native synchronous call returns.
        // Only the digest and signature cross the ABI; never a private key.
        // The Go adapter verifies that the callback signed the correct digest.
        internal int SignCallback(IntPtr context, IntPtr digest, IntPtr signature)
        {
            if (digest == IntPtr.Zero || signature == IntPtr.Zero) return 1;
            byte[] input = new byte[32];
            byte[] output = null;
            try
            {
                Marshal.Copy(input, 0, signature, 32);
                Marshal.Copy(input, 0, IntPtr.Add(signature, 32), 32);
                Marshal.Copy(digest, input, 0, 32);
                output = SignDigest(input);
                Marshal.Copy(output, 0, signature, 64);
                return 0;
            }
            catch (Exception)
            {
                // Never propagate a managed exception across native code.
                return 1;
            }
            finally
            {
                Array.Clear(input, 0, input.Length);
                if (output != null) Array.Clear(output, 0, output.Length);
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                if (signer != null) { signer.Dispose(); signer = null; }
                if (key != null) { key.Dispose(); key = null; }
            }
        }
    }
}
