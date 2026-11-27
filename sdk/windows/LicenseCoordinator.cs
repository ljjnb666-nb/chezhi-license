// One fixed card/device/trust context. Native work stays off the UI thread.
// Logical cancellation invalidates late completion, never releases a live
// CNG handle or allows a second concurrent native call.
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Chezhi.Licensing
{
    internal sealed class LicenseCoordinator : IDisposable
    {
        private readonly object gate=new object();
        private readonly NativeLicenseClient client;
        private readonly AuthorizationState state=new AuthorizationState();
        private WindowsDeviceKey device;
        private byte[] card;
        private bool closing;
        private Task<bool> pending;

        // Ownership of device transfers only on successful construction.
        internal LicenseCoordinator(NativeLicenseClient sdk,WindowsDeviceKey key,byte[] cardBytes)
        {
            if(sdk==null||key==null||cardBytes==null||cardBytes.Length==0||cardBytes.Length>100)
                throw new ArgumentException("Invalid authorization context.");
            client=sdk;device=key;card=(byte[])cardBytes.Clone();
        }

        internal AuthorizationPhase Phase {get{return state.Phase;}}
        internal bool CanStartProtectedOperation {get{return state.CanStartProtectedOperation;}}
        internal bool Busy {get{return state.Busy;}}
        internal void NetworkChanged(bool reachable) {state.NetworkChanged(reachable);}
        internal void CancelAttempt() {state.CancelAttempt();}

        internal Task<bool> VerifyAsync(LicenseOperation operation)
        {
            lock(gate)
            {
                if(closing || pending!=null) return null;
                AuthorizationAttempt ticket=state.TryBegin(operation);
                if(ticket==null) return null;
                try
                {
                    pending=Task.Factory.StartNew(delegate
                    {
                        LicenseStatus status=LicenseStatus.InternalFailure;
                        LicenseMetadata result=null;
                        try {status=client.Authorize(operation,card,device,out result);}
                        catch(Exception) {status=LicenseStatus.InternalFailure;}
                        lock(gate)
                        {
                            try {return state.Complete(ticket,status,result);}
                            finally
                            {
                                pending=null;
                                if(closing) Release();
                            }
                        }
                    },CancellationToken.None,TaskCreationOptions.None,TaskScheduler.Default);
                    return pending;
                }
                catch
                {
                    state.Complete(ticket,LicenseStatus.InternalFailure,null);
                    throw;
                }
            }
        }

        private void Release()
        {
            if(card!=null) {Array.Clear(card,0,card.Length);card=null;}
            if(device!=null) {device.Dispose();device=null;}
        }
        // Returns immediately; native call cannot yet be interrupted. Its
        // completion is invalidated, and handles are released only after it
        // returns. App should not block the UI thread waiting for disposal.
        public void Dispose()
        {
            lock(gate)
            {
                if(closing) return;
                closing=true;state.Shutdown();
                if(pending==null) Release();
            }
        }
    }
}
