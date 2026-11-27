using System;
using System.Threading;
using Chezhi.Licensing;

internal static class AuthorizationStateSmoke
{
    private sealed class Clock : IAuthorizationClock
    {
        internal long Utc=1700000000,Mono=1000;
        public long UnixSeconds {get{return Utc;}}
        public long MonotonicMilliseconds {get{return Mono;}}
    }
    private static void Check(bool ok,string reason) {if(!ok) throw new Exception(reason);}
    private static LicenseMetadata Meta(Clock c,ulong rev)
    {return new LicenseMetadata(rev,c.Utc,c.Utc+300,c.Utc+86400);}
    private static AuthorizationAttempt Start(AuthorizationState s)
    {
        AuthorizationAttempt a=s.TryBegin(LicenseOperation.Validate);
        Check(a!=null && s.Busy && !s.CanStartProtectedOperation,"start/in-flight grant");
        return a;
    }
    private static void Run()
    {
        Clock c=new Clock();AuthorizationState s=new AuthorizationState(c);
        Check(!s.CanStartProtectedOperation,"startup grant");
        AuthorizationAttempt a=Start(s);
        Check(s.TryBegin(LicenseOperation.Activate)==null,"parallel native call");
        Check(s.Complete(a,LicenseStatus.Ok,Meta(c,7)) && s.CanStartProtectedOperation,"valid grant");
        Check(!s.Complete(a,LicenseStatus.Ok,Meta(c,7)),"replayed completion");
        // Offline->online is not an authorization decision.
        s.NetworkChanged(false);Check(!s.CanStartProtectedOperation && s.TryBegin(LicenseOperation.Validate)==null,"offline grant");
        s.NetworkChanged(true);Check(!s.CanStartProtectedOperation,"network recovery grant");
        a=Start(s);s.NetworkChanged(false);s.NetworkChanged(true);
        Check(s.Busy && s.TryBegin(LicenseOperation.Validate)==null,"physical overlap after invalidation");
        Check(!s.Complete(a,LicenseStatus.Ok,Meta(c,7)) && !s.CanStartProtectedOperation,"stale success after network change");
        a=Start(s);s.CancelAttempt();
        Check(s.Busy && !s.Complete(a,LicenseStatus.Ok,Meta(c,7)),"cancelled grant");
        a=Start(s);s.Complete(a,LicenseStatus.Unavailable,null);
        Check(s.Phase==AuthorizationPhase.NetworkUnavailable && !s.CanStartProtectedOperation,"network classified as denial");
        s.NetworkChanged(true);Check(s.TryBegin(LicenseOperation.Validate)==null,"network backoff bypass");
        c.Mono+=5000;a=Start(s);s.Complete(a,LicenseStatus.RetryLater,null);
        c.Mono+=59999;Check(s.TryBegin(LicenseOperation.Validate)==null,"rate backoff bypass");
        c.Mono++;a=Start(s);s.Complete(a,LicenseStatus.Denied,null);
        s.NetworkChanged(false);s.NetworkChanged(true);
        Check(s.Phase==AuthorizationPhase.Denied && !s.CanStartProtectedOperation,"denial erased by network");
        a=Start(s);Check(!s.Complete(a,LicenseStatus.Ok,Meta(c,6)) && s.Phase==AuthorizationPhase.SecurityError,"revision rollback");
        a=Start(s);Check(!s.Complete(a,LicenseStatus.Ok,new LicenseMetadata(7,c.Utc,c.Utc+301,0)),"overlong TTL");
        a=Start(s);Check(!s.Complete(a,LicenseStatus.Ok,new LicenseMetadata(7,c.Utc,c.Utc+300,c.Utc+299)),"license expiry exceeded");
        a=Start(s);Check(!s.Complete(a,LicenseStatus.Ok,new LicenseMetadata(7,c.Utc+1,c.Utc+300,0)),"future credential");
        a=Start(s);Check(s.Complete(a,LicenseStatus.Ok,Meta(c,8)),"valid refresh");
        c.Mono+=300000;Check(!s.CanStartProtectedOperation && s.Phase==AuthorizationPhase.Expired,"monotonic expiry");
        a=Start(s);Check(s.Complete(a,LicenseStatus.Ok,Meta(c,8)),"valid again");
        c.Utc--;Check(!s.CanStartProtectedOperation,"wall clock backwards");
        c.Utc++;a=Start(s);c.Mono+=300000;
        Check(!s.Complete(a,LicenseStatus.Ok,Meta(c,8)) && s.Phase==AuthorizationPhase.Expired,"slow call extended deadline");
        a=Start(s);s.RequireIdentityRecovery();
        Check(!s.Complete(a,LicenseStatus.Ok,Meta(c,8)) && s.TryBegin(LicenseOperation.Activate)==null &&
            s.Phase==AuthorizationPhase.RecoveryRequired,"recovery silently enrolled");
        s.Shutdown();Check(s.Phase==AuthorizationPhase.Stopped && !s.CanStartProtectedOperation,"shutdown grant");

        c=new Clock();s=new AuthorizationState(c);a=Start(s);s.Shutdown();
        Check(!s.Complete(a,LicenseStatus.Ok,Meta(c,1)) && s.Phase==AuthorizationPhase.Stopped,"late shutdown completion");
        c=new Clock();s=new AuthorizationState(c);a=Start(s);s.Complete(a,LicenseStatus.Ok,Meta(c,1));
        c.Mono--;Check(!s.CanStartProtectedOperation && s.TryBegin(LicenseOperation.Validate)==null,"monotonic rollback");

        foreach(LicenseStatus status in new[]{LicenseStatus.InvalidInput,LicenseStatus.UntrustedResponse,LicenseStatus.InternalFailure,LicenseStatus.Cancelled,(LicenseStatus)99})
        {
            c=new Clock();s=new AuthorizationState(c);a=Start(s);
            Check(!s.Complete(a,status,Meta(c,1)) && !s.CanStartProtectedOperation,"nonzero native status granted");
        }
        byte[] output=new byte[32];output[7]=7;output[15]=10;output[23]=20;
        LicenseMetadata m=LicenseMetadata.Decode(output);
        Check(m.Revision==7 && m.IssuedAt==10 && m.ExpiresAt==20 && m.LicenseExpiresAt==0,"ABI metadata");
        output[8]=0x80;bool rejected=false;
        try{LicenseMetadata.Decode(output);}catch(ArgumentException){rejected=true;}
        Check(rejected,"signed timestamp overflow");

        c=new Clock();s=new AuthorizationState(c);
        AuthorizationAttempt x=null,y=null;
        Thread t1=new Thread(delegate(){x=s.TryBegin(LicenseOperation.Activate);});
        Thread t2=new Thread(delegate(){y=s.TryBegin(LicenseOperation.Validate);});
        t1.Start();t2.Start();t1.Join();t2.Join();
        Check((x==null)!=(y==null),"thread overlap");
        Check(s.Complete(x??y,LicenseStatus.Ok,Meta(c,1)),"thread winner");
        Console.WriteLine("PASS authorization state: single-flight, stale completion, fail-closed network, backoff, revision, time, recovery and shutdown");
    }
    private static int Main()
    {try{Run();return 0;}catch(Exception e){Console.Error.WriteLine(e.Message);return 1;}}
}
