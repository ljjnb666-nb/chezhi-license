// UI-independent P4.3 online authorization state machine.
// One instance belongs to one fixed card, enrolled device and trust scope.
// No network, native handles, cached credentials or offline grant here.
using System;
using System.Diagnostics;

namespace Chezhi.Licensing
{
    internal enum LicenseOperation { Activate=1, Validate=2, Renew=3 }
    internal enum LicenseStatus { Ok=0, InvalidInput=1, Unavailable=2, Denied=3,
        RetryLater=4, UntrustedResponse=5, InternalFailure=6, Cancelled=7 }
    internal enum AuthorizationPhase
    {
        NeedsVerification, Checking, Authorized, NetworkUnavailable, RetryLater,
        Denied, SecurityError, LocalError, RecoveryRequired, Expired, Stopped
    }

    internal sealed class LicenseMetadata
    {
        internal readonly ulong Revision;
        internal readonly long IssuedAt, ExpiresAt, LicenseExpiresAt;
        internal LicenseMetadata(ulong revision,long issued,long expires,long licenseExpires)
        {
            Revision=revision;IssuedAt=issued;ExpiresAt=expires;LicenseExpiresAt=licenseExpires;
        }

        // C ABI outputs exactly four unsigned/big-endian 64-bit fields
        // (the three timestamps must fit positive signed Unix seconds).
        internal static LicenseMetadata Decode(byte[] b)
        {
            if(b==null || b.Length!=32) throw new ArgumentException("Invalid SDK metadata.");
            ulong[] values=new ulong[4];
            for(int i=0;i<4;i++)
                for(int j=0;j<8;j++) values[i]=(values[i]<<8)|b[i*8+j];
            if(values[1]>Int64.MaxValue || values[2]>Int64.MaxValue || values[3]>Int64.MaxValue)
                throw new ArgumentException("Invalid SDK timestamp.");
            return new LicenseMetadata(values[0],(long)values[1],(long)values[2],(long)values[3]);
        }
        internal bool IsValid(long utc)
        {
            return Revision>0 && Revision<=(ulong)Int64.MaxValue &&
                IssuedAt>0 && IssuedAt<=utc && ExpiresAt>utc &&
                ExpiresAt>IssuedAt && ExpiresAt-IssuedAt<=300 &&
                (LicenseExpiresAt==0 || LicenseExpiresAt>=ExpiresAt);
        }
    }

    internal interface IAuthorizationClock
    {
        long UnixSeconds { get; }
        long MonotonicMilliseconds { get; }
    }
    internal sealed class AuthorizationClock : IAuthorizationClock
    {
        private static readonly DateTime Epoch=new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc);
        private readonly Stopwatch elapsed=Stopwatch.StartNew();
        public long UnixSeconds { get { return (DateTime.UtcNow-Epoch).Ticks/TimeSpan.TicksPerSecond; } }
        public long MonotonicMilliseconds { get { return elapsed.ElapsedMilliseconds; } }
    }

    // The ticket is an object identity, not a reusable integer counter.
    internal sealed class AuthorizationAttempt
    {
        internal readonly LicenseOperation Operation;
        internal readonly long StartedAt;
        internal AuthorizationAttempt(LicenseOperation op,long start) {Operation=op;StartedAt=start;}
    }

    internal sealed class AuthorizationState
    {
        private readonly object gate=new object();
        private readonly IAuthorizationClock clock;
        private AuthorizationPhase phase=AuthorizationPhase.NeedsVerification;
        private AuthorizationAttempt inFlight;
        private bool invalidated, knownOffline, terminal;
        private long lastMono, retryAt, deadline, issued, expires;
        private ulong highestRevision;

        internal AuthorizationState() : this(new AuthorizationClock()) {}
        internal AuthorizationState(IAuthorizationClock source)
        {
            if(source==null) throw new ArgumentNullException("source");
            clock=source;
            lastMono=clock.MonotonicMilliseconds;
            if(lastMono<0) throw new ArgumentException("Invalid monotonic clock.");
        }

        private void ClearGrant()
        {
            deadline=0;issued=0;expires=0;
        }
        private void Invalidate(AuthorizationPhase next)
        {
            ClearGrant();
            if(inFlight!=null) invalidated=true;
            phase=next;
        }
        private long ReadMonotonic()
        {
            long now=clock.MonotonicMilliseconds;
            if(now<lastMono)
            {
                // Clock rollback is a terminal local security failure for
                // this instance, not a way to lengthen an authorization.
                if(!terminal) {terminal=true;Invalidate(AuthorizationPhase.SecurityError);}
                return lastMono;
            }
            lastMono=now;
            return now;
        }
        private void Refresh(long now,long utc)
        {
            if(phase==AuthorizationPhase.Authorized &&
                (now>=deadline || utc<issued || utc>=expires))
                Invalidate(AuthorizationPhase.Expired);
        }

        internal AuthorizationPhase Phase
        {
            get {lock(gate){Refresh(ReadMonotonic(),clock.UnixSeconds);return phase;}}
        }
        internal bool Busy {get {lock(gate){return inFlight!=null;}}}

        // This is the admission check immediately before each protected
        // operation. It does not authorize cleanup, which must always be
        // available, and it must not be replaced with a UI color/label.
        internal bool CanStartProtectedOperation
        {
            get
            {
                lock(gate)
                {
                    Refresh(ReadMonotonic(),clock.UnixSeconds);
                    return !terminal && !knownOffline && inFlight==null && phase==AuthorizationPhase.Authorized;
                }
            }
        }

        internal AuthorizationAttempt TryBegin(LicenseOperation op)
        {
            lock(gate)
            {
                long now=ReadMonotonic();
                Refresh(now,clock.UnixSeconds);
                if(terminal || knownOffline || inFlight!=null || now<retryAt ||
                    (op!=LicenseOperation.Activate && op!=LicenseOperation.Validate && op!=LicenseOperation.Renew))
                    return null;
                // A refresh in flight never grants admission based on a
                // previous success. Only the current verified result does.
                ClearGrant();
                invalidated=false;
                inFlight=new AuthorizationAttempt(op,now);
                phase=AuthorizationPhase.Checking;
                return inFlight;
            }
        }

        private static long AddBounded(long a,long b)
        {
            return a>Int64.MaxValue-b ? Int64.MaxValue : a+b;
        }

        // Every successfully started native call must complete exactly
        // once, including exceptions. Invalidation doesn't release the
        // physical in-flight slot until this callback arrives.
        internal bool Complete(AuthorizationAttempt attempt,LicenseStatus status,LicenseMetadata data)
        {
            lock(gate)
            {
                if(attempt==null || !Object.ReferenceEquals(attempt,inFlight)) return false;
                long now=ReadMonotonic(),utc=clock.UnixSeconds;
                inFlight=null;
                if(terminal || invalidated || knownOffline) return false;
                ClearGrant();
                switch(status)
                {
                    case LicenseStatus.Ok:
                        if(data==null || !data.IsValid(utc) || data.Revision<highestRevision)
                        {phase=AuthorizationPhase.SecurityError;return false;}
                        // Use the request start as the conservative anchor
                        // for the signed lifetime, AND cap by current UTC
                        // remaining time. No wall-clock rollback can extend it.
                        long signedMs=(data.ExpiresAt-data.IssuedAt)*1000;
                        long remainingMs=(data.ExpiresAt-utc)*1000;
                        deadline=Math.Min(AddBounded(attempt.StartedAt,signedMs),AddBounded(now,remainingMs));
                        highestRevision=data.Revision;
                        issued=data.IssuedAt;expires=data.ExpiresAt;
                        if(now>=deadline) {Invalidate(AuthorizationPhase.Expired);return false;}
                        retryAt=0;phase=AuthorizationPhase.Authorized;return true;
                    case LicenseStatus.Unavailable:
                        retryAt=AddBounded(now,5000);phase=AuthorizationPhase.NetworkUnavailable;break;
                    case LicenseStatus.RetryLater:
                        retryAt=AddBounded(now,60000);phase=AuthorizationPhase.RetryLater;break;
                    case LicenseStatus.Denied: phase=AuthorizationPhase.Denied;break;
                    case LicenseStatus.UntrustedResponse: phase=AuthorizationPhase.SecurityError;break;
                    case LicenseStatus.Cancelled: phase=AuthorizationPhase.NeedsVerification;break;
                    default: phase=AuthorizationPhase.LocalError;break;
                }
                return false;
            }
        }

        // A network signal is only a negative hint, never a grant. Restored
        // reachability needs a fresh online proof; do not erase an explicit
        // denial/security/recovery state on network changes.
        internal void NetworkChanged(bool reachable)
        {
            lock(gate)
            {
                ReadMonotonic();
                if(terminal) return;
                knownOffline=!reachable;
                if(!reachable)
                {
                    if(phase==AuthorizationPhase.Authorized || phase==AuthorizationPhase.Checking ||
                        phase==AuthorizationPhase.NeedsVerification || phase==AuthorizationPhase.Expired)
                        Invalidate(AuthorizationPhase.NetworkUnavailable);
                }
                else if(phase==AuthorizationPhase.NetworkUnavailable)
                    phase=AuthorizationPhase.NeedsVerification;
            }
        }

        internal void CancelAttempt()
        {
            lock(gate)
            {
                if(terminal) return;
                if(inFlight!=null) Invalidate(knownOffline?AuthorizationPhase.NetworkUnavailable:AuthorizationPhase.NeedsVerification);
            }
        }
        internal void RequireIdentityRecovery()
        {
            lock(gate)
            {
                if(terminal) return;
                terminal=true;
                Invalidate(AuthorizationPhase.RecoveryRequired);
            }
        }
        internal void Shutdown()
        {
            lock(gate)
            {
                terminal=true;
                Invalidate(AuthorizationPhase.Stopped);
            }
        }
    }
}
