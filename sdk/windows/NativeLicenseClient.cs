// .NET Framework 4.x bridge. Trust values must come from the authenticated
// distribution manifest, never from the API, user input, or a DLL itself.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Chezhi.Licensing
{
    internal sealed class NativeLicenseClient
    {
        private const uint SearchDllLoadDir=0x100, SearchSystem32=0x800;
        private static readonly object LoadGate=new object();
        private static IntPtr module;
        private static string loadedPath;
        private static byte[] loadedHash;
        private static AuthorizeFn invoke;
        private static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);

        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        private static extern IntPtr LoadLibraryEx(string path,IntPtr reserved,uint flags);
        [DllImport("kernel32.dll",CharSet=CharSet.Ansi,ExactSpelling=true,SetLastError=true)]
        private static extern IntPtr GetProcAddress(IntPtr module,string name);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint VersionFn();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int SignFn(IntPtr context,IntPtr digest,IntPtr signature);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int AuthorizeFn(
            [In] byte[] origin,uint originLen,[In] byte[] deployment,[In] byte[] trusted,
            [In] byte[] card,uint cardLen,[In] byte[] point,SignFn signer,IntPtr context,
            uint op,[In,Out] byte[] output,uint outputLen);

        private readonly byte[] origin,scope,publicKey;

        private static bool Equal(byte[] a,byte[] b)
        {
            if(a==null||b==null||a.Length!=b.Length) return false;
            int diff=0;for(int i=0;i<a.Length;i++) diff|=a[i]^b[i];
            return diff==0;
        }
        private static Delegate Resolve(string name,Type type)
        {
            IntPtr p=GetProcAddress(module,name);
            if(p==IntPtr.Zero) throw new InvalidOperationException("Missing SDK export.");
            return Marshal.GetDelegateForFunctionPointer(p,type);
        }

        private static void Load(string path,byte[] digest)
        {
            if(IntPtr.Size!=8 || String.IsNullOrEmpty(path) || !Path.IsPathRooted(path) ||
                digest==null || digest.Length!=32) throw new ArgumentException("Invalid native SDK configuration.");
            path=Path.GetFullPath(path);
            lock(LoadGate)
            {
                if(module!=IntPtr.Zero)
                {
                    if(invoke==null || !String.Equals(path,loadedPath,StringComparison.OrdinalIgnoreCase) ||
                        !Equal(digest,loadedHash)) throw new InvalidOperationException("SDK already loaded or unavailable.");
                    return;
                }
                // Caller must use an ACL-protected, local installation
                // directory. Reject reparse points on this path and hold
                // the file against writes/deletion while hashing/loading.
                for(string p=path;!String.IsNullOrEmpty(p);p=Path.GetDirectoryName(p))
                    if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)
                        throw new IOException("Unexpected SDK reparse point.");
                using(FileStream f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
                using(SHA256 hash=SHA256.Create())
                {
                    if(!Equal(hash.ComputeHash(f),digest)) throw new CryptographicException("SDK integrity mismatch.");
                    // System32 and the trusted DLL directory only. No PATH
                    // or working-directory lookup. Never unload Go runtime.
                    module=LoadLibraryEx(path,IntPtr.Zero,SearchDllLoadDir|SearchSystem32);
                    if(module==IntPtr.Zero) throw new InvalidOperationException("Cannot load native SDK.");
                    loadedPath=path;loadedHash=(byte[])digest.Clone();
                    if(((VersionFn)Resolve("ChezhiLicenseABIVersion",typeof(VersionFn)))()!=1)
                        throw new InvalidOperationException("Unsupported SDK ABI.");
                    invoke=(AuthorizeFn)Resolve("ChezhiLicenseAuthorize",typeof(AuthorizeFn));
                }
            }
        }

        internal NativeLicenseClient(string dll,byte[] digest,string httpsOrigin,byte[] deployment,byte[] trusted)
        {
            if(String.IsNullOrEmpty(httpsOrigin) || deployment==null || deployment.Length!=32 ||
                trusted==null || trusted.Length!=32) throw new ArgumentException("Invalid SDK trust configuration.");
            origin=Utf8.GetBytes(httpsOrigin);
            if(origin.Length>2048) throw new ArgumentException("Origin too long.");
            scope=(byte[])deployment.Clone();publicKey=(byte[])trusted.Clone();
            Load(dll,digest);
        }

        internal LicenseStatus Authorize(LicenseOperation operation,byte[] card,WindowsDeviceKey device,out LicenseMetadata metadata)
        {
            metadata=null;
            if(card==null||card.Length==0||card.Length>100||device==null) return LicenseStatus.InvalidInput;
            byte[] output=new byte[32];
            SignFn signer=device.SignCallback;
            try
            {
                int status=invoke(origin,(uint)origin.Length,scope,publicKey,card,(uint)card.Length,
                    device.PublicPoint,signer,IntPtr.Zero,(uint)operation,output,32);
                if(status!=0)
                {
                    foreach(byte b in output) if(b!=0) return LicenseStatus.UntrustedResponse;
                    return status>=1&&status<=7?(LicenseStatus)status:LicenseStatus.InternalFailure;
                }
                try {metadata=LicenseMetadata.Decode(output);return LicenseStatus.Ok;}
                catch(ArgumentException) {return LicenseStatus.UntrustedResponse;}
            }
            finally
            {
                GC.KeepAlive(signer);GC.KeepAlive(device);
                Array.Clear(output,0,output.Length);
            }
        }
    }
}
