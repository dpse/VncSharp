// VncSharp - .NET VNC Client Library
// Copyright (C) 2008 David Humphrey
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

using System;
using System.Diagnostics;
using System.Drawing;
using System.Media;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
// ReSharper disable CompareOfFloatsByEqualityOperator
// ReSharper disable ArrangeAccessorOwnerBody

namespace VncSharp
{
    using System.IO;
    using System.Threading.Tasks;

    /// <summary>
	/// Delegate definition of an Event Handler used to indicate a Framebuffer Update has been received.
	/// </summary>
	public delegate void VncUpdateHandler(object sender, VncEventArgs e);
	
	public class VncClient
	{
		private RfbProtocol rfb;			// The protocol object handling all communication with server.
		private byte securityType;			// The type of Security agreed upon by client/server
		private EncodedRectangleFactory factory;
		private Thread worker;				// To request and read in-coming updates from server
		private ManualResetEvent done;		// Used to tell the worker thread to die cleanly
		private IVncInputPolicy inputPolicy;// A mouse/keyboard input strategy
		private bool viewOnlyMode = false;

		/// <summary>
		/// Raised when the connection to the remote host is lost.
		/// </summary>
		public event EventHandler ConnectionLost;

		/// <summary>
		/// Raised when the server caused the local clipboard to be filled.
		/// </summary>
		public event EventHandler ServerCutText;

		/// <summary>
		/// Gets the Framebuffer representing the remote server's desktop geometry.
		/// </summary>
		public Framebuffer Framebuffer { get; private set; }

		/// <summary>
		/// Gets/Sets if full screen refresh is required (forced) from the connected server.
		/// </summary>
		public bool FullScreenRefresh { get; set; }

		/// <summary>
		/// Gets the hostname of the remote desktop
		/// </summary>
		public string HostName
		{
			get { return Framebuffer.DesktopName; }
		}

		/// <summary>
		/// Returns True if the VncClient object is View-Only, meaning no mouse/keyboard events are being sent.
		/// </summary>
		public bool ViewOnly
	    {
	        get {	return viewOnlyMode;	}
			set {	viewOnlyMode = value;
					// Allocate the inputPolicy if there is a connection
					if (rfb != null)
					{	if (viewOnlyMode)
							inputPolicy = new VncViewInputPolicy(rfb);
						else
							inputPolicy = new VncDefaultInputPolicy(rfb);
					}
				}
	    }

	    // Just for API compat, since I've added viewOnly
		public bool Connect(string host, int display, int port)
		{
			return Connect(host, display, port, viewOnlyMode);
		}

		public Task<bool> ConnectAsync(string host, int display, int port)
		{
			return ConnectAsync(host, display, port, viewOnlyMode);
		}

        /// <summary>
        /// Connect to a VNC Host and determine which type of Authentication it uses. If the host uses Password Authentication, a call to Authenticate() will be required.
        /// </summary>
        /// <param name="host">The IP Address or Host Name of the VNC Host.</param>
        /// <param name="display">The Display number (used on Unix hosts).</param>
        /// <param name="port">The Port number used by the Host, usually 5900.</param>
        /// <param name="viewOnly">True if mouse/keyboard events are to be ignored.</param>
        /// <returns>Returns True if the VNC Host requires a Password to be sent after Connect() is called, otherwise False.</returns>
        public bool Connect(string host, int display, int port, bool viewOnly)
        {
            return ConnectAsync(host, display, port, viewOnly).Result;
        }

        public bool Connect(Stream stream, bool viewOnly)
        {
            return ConnectAsync(stream, viewOnly).Result;
        }

		/// <summary>
		/// Connect to a VNC Host and determine which type of Authentication it uses. If the host uses Password Authentication, a call to Authenticate() will be required.
		/// </summary>
		/// <param name="host">The IP Address or Host Name of the VNC Host.</param>
		/// <param name="display">The Display number (used on Unix hosts).</param>
		/// <param name="port">The Port number used by the Host, usually 5900.</param>
		/// <param name="viewOnly">True if mouse/keyboard events are to be ignored.</param>
		/// <returns>Returns True if the VNC Host requires a Password to be sent after Connect() is called, otherwise False.</returns>
		public async Task<bool> ConnectAsync(string host, int display, int port, bool viewOnly, CancellationToken ct = default)
		{
			if (host == null) throw new ArgumentNullException(nameof(host));

			// If a diplay number is specified (used to connect to Unix servers)
			// it must be 0 or greater.  This gets added to the default port number
			// in order to determine where the server will be listening for connections.
			if (display < 0) throw new ArgumentOutOfRangeException(nameof(display), display, "Display number must be non-negative.");
			port += display;
			
			this.CreateRfbProtocol(viewOnly);

            // Connect and determine version of server, and set client protocol version to match			
			try
            {
                await rfb.ConnectAsync(host, port, ct);
                return await this.ContinueConnectAsync(ct);
            } catch (Exception e) {
				throw new VncProtocolException("Unable to connect to the server. Error was: " + e.Message, e);
			}			
		}

        public async Task<bool> ConnectAsync(Stream stream, bool viewOnly, CancellationToken ct = default)
		{
            if (stream == null) throw new ArgumentNullException(nameof(stream));
			
			this.CreateRfbProtocol(viewOnly);
			
			// Connect and determine version of server, and set client protocol version to match			
			try {
				rfb.Connect(stream);
                return await this.ContinueConnectAsync(ct);
			} catch (Exception e) {
				throw new VncProtocolException("Unable to connect to the server. Error was: " + e.Message, e);
			}			
		}

		/// <summary>
		/// Connect to a VNC Host and determine which type of Authentication it uses. If the host uses Password Authentication, a call to Authenticate() will be required. Default Display and Port numbers are used.
		/// </summary>
		/// <param name="host">The IP Address or Host Name of the VNC Host.</param>
		/// <returns>Returns True if the VNC Host requires a Password to be sent after Connect() is called, otherwise False.</returns>
		public bool Connect(string host)
		{
			return Connect(host, 0, 5900);
		}

		public Task<bool> ConnectAsync(string host)
		{
			return ConnectAsync(host, 0, 5900);
		}

		/// <summary>
		/// Connect to a VNC Host and determine which type of Authentication it uses. If the host uses Password Authentication, a call to Authenticate() will be required. The Port number is calculated based on the Display.
		/// </summary>
		/// <param name="host">The IP Address or Host Name of the VNC Host.</param>
		/// <param name="display">The Display number (used on Unix hosts).</param>
		/// <returns>Returns True if the VNC Host requires a Password to be sent after Connect() is called, otherwise False.</returns>
		public bool Connect(string host, int display)
		{
			return Connect(host, display, 5900);
		}

		public Task<bool> ConnectAsync(string host, int display)
		{
			return ConnectAsync(host, display, 5900);
		}

        private async Task<bool> ContinueConnectAsync(CancellationToken ct)
        {
            await this.rfb.ReadProtocolVersion(ct);

            // Handle possible repeater connection
            if (this.rfb.ServerVersion == 0.0)
            {
                await this.rfb.WriteProxyAddress(ct);
                // Now we are connected to the real server; read the protocol version of the 
                // server
                await this.rfb.ReadProtocolVersion(ct);
                // Resume normal handshake and protocol
            }

            await this.rfb.WriteProtocolVersion(ct);

            // Figure out which type of authentication the server uses
            var types = await this.rfb.ReadSecurityTypes(ct);

            // Based on what the server sends back in the way of supported Security Types, one of
            // two things will need to be done: either the server will reject the connection (i.e., type = 0),
            // or a list of supported types will be sent, of which we need to choose and use one.
            if (types.Length <= 0)
                // Something is wrong, since we should have gotten at least 1 Security Type
                throw new VncProtocolException(
                    "Protocol Error Connecting to Server. The Server didn't send any Security Types during the initial handshake.");
            if (types[0] == 0)
            {
                // The server is not able (or willing) to accept the connection.
                // A message follows indicating why the connection was dropped.
                throw new VncProtocolException(
                    "Connection Failed. The server rejected the connection for the following reason: "
                    + this.rfb.ReadSecurityFailureReason(ct));
            }

            this.securityType = this.GetSupportedSecurityType(types);
            Debug.Assert(this.securityType > 0, "Unknown Security Type(s)", "The server sent one or more unknown Security Types.");

            await this.rfb.WriteSecurityType(this.securityType, ct);

            // Protocol 3.8 states that a SecurityResult is still sent when using NONE (see 6.2.1)
            if (this.rfb.ServerVersion != 3.8f || this.securityType != 1) return this.securityType > 1;
            if (await this.rfb.ReadSecurityResult(ct) > 0)
            {
                // For some reason, the server is not accepting the connection.  Get the
                // reason and throw an exception
                throw new VncProtocolException(
                    "Unable to Connecto to the Server. The Server rejected the connection for the following reason: "
                    + this.rfb.ReadSecurityFailureReason(ct));
            }

            return this.securityType > 1;
        }

        private void CreateRfbProtocol(bool viewOnly)
        {
            this.rfb = new RfbProtocol();

            this.viewOnlyMode = viewOnly;
            if (viewOnly)
            {
                this.inputPolicy = new VncViewInputPolicy(this.rfb);
            }
            else
            {
                this.inputPolicy = new VncDefaultInputPolicy(this.rfb);
            }
        }

		/// <summary>
		/// Examines a list of Security Types supported by a VNC Server and chooses one that the Client supports.  See 6.1.2 of the RFB Protocol document v. 3.8.
		/// </summary>
		/// <param name="types">An array of bytes representing the Security Types supported by the VNC Server.</param>
		/// <returns>A byte that represents the Security Type to be used by the Client.</returns>
		private byte GetSupportedSecurityType(byte[] types)
		{
			// Pick the first match in the list of given types.  If you want to add support for new
			// security types, do it here:
			for (var i = 0; i < types.Length; ++i) {
				if (   types[i] == 1  	// None
					|| types[i] == 2	// VNC Authentication
// TODO: None of the following are currently supported -------------------
//					|| types[i] == 5	// RA2
//					|| types[i] == 6    // RA2ne
//					|| types[i] == 16   // Tight
//					|| types[i] == 17 	// Ultra
//					|| types[i] == 18 	// TLS
				   ) return types[i];
			}
			return 0;
		}

		/// <summary>
		/// Use a password to authenticate with a VNC Host. NOTE: This is only necessary if Connect() returns TRUE.
		/// </summary>
		/// <param name="password">The password to use.</param>
		/// <returns>Returns True if Authentication worked, otherwise False.</returns>
		public async Task<bool> Authenticate(string password, CancellationToken ct = default)
		{
			if (password == null) throw new ArgumentNullException(nameof(password));
			
			// If new Security Types are supported in future, add the code here.  For now, only 
			// VNC Authentication is supported.
			if (securityType == 2) {
			    await PerformVncAuthentication(password, ct);
			} else {
				throw new NotSupportedException("Unable to Authenticate with Server. The Server uses an Authentication scheme unknown to the client.");
			}
			
			if (await rfb.ReadSecurityResult(ct) == 0) {
				return true;
			}
		    // Authentication failed, and if the server is using Protocol version 3.8, a 
		    // plain text message follows indicating why the error happend.  I'm not 
		    // currently using this message, but it is read here to clean out the stream.
		    // In earlier versions of the protocol, the server will just drop the connection.
		    if (rfb.ServerVersion == 3.8) await rfb.ReadSecurityFailureReason(ct);
		    rfb.Close();	// TODO: Is this the right place for this???
		    return false;
		}

		/// <summary>
		/// Performs VNC Authentication using VNC DES encryption.  See the RFB Protocol doc 6.2.2.
		/// </summary>
		/// <param name="password">A string containing the user's password in clear text format.</param>
		private async Task PerformVncAuthentication(string password, CancellationToken ct = default)
		{
			var challenge = await rfb.ReadSecurityChallenge(ct);
			await rfb.WriteSecurityResponse(EncryptChallenge(password, challenge), ct);
		}

		/// <summary>
		/// Encrypts a challenge using the specified password. See RFB Protocol Document v. 3.8 section 6.2.2.
		/// </summary>
		/// <param name="password">The user's password.</param>
		/// <param name="challenge">The challenge sent by the server.</param>
		/// <returns>Returns the encrypted challenge.</returns>
		private byte[] EncryptChallenge(string password, byte[] challenge)
		{
			var key = new byte[8];

			// Key limited to 8 bytes max.
		    Encoding.ASCII.GetBytes(password, 0, password.Length >= 8 ? 8 : password.Length, key, 0);

		    // VNC uses reverse byte order in key
            for (var i = 0; i < 8; i++)
                key[i] = (byte)( ((key[i] & 0x01) << 7) |
                                 ((key[i] & 0x02) << 5) |
                                 ((key[i] & 0x04) << 3) |
                                 ((key[i] & 0x08) << 1) |
                                 ((key[i] & 0x10) >> 1) |
                                 ((key[i] & 0x20) >> 3) |
                                 ((key[i] & 0x40) >> 5) |
                                 ((key[i] & 0x80) >> 7)  );

            // VNC uses DES, not 3DES as written in some documentation
            DES des = new DESCryptoServiceProvider()
            {
                Padding = PaddingMode.None,
                Mode = CipherMode.ECB
            };
            var enc = des.CreateEncryptor(key, null); 

			var response = new byte[16];
			enc.TransformBlock(challenge, 0, challenge.Length, response, 0);
			
			return response;
		}

		/// <summary>
		/// Finish setting-up protocol with VNC Host.  Should be called after Connect and Authenticate (if password required).
		/// </summary>
		public async Task Initialize(int bitsPerPixel, int depth, CancellationToken ct = default)
		{
			// Finish initializing protocol with host
			await rfb.WriteClientInitialisation(true, ct);  // Allow the desktop to be shared
			Framebuffer = await rfb.ReadServerInit(bitsPerPixel, depth, ct);

			await rfb.WriteSetEncodings(new uint[] {	RfbProtocol.ZRLE_ENCODING,
			                                    RfbProtocol.HEXTILE_ENCODING, 
											//	RfbProtocol.CORRE_ENCODING, // CoRRE is buggy in some hosts, so don't bother using
												RfbProtocol.RRE_ENCODING,
												RfbProtocol.COPYRECT_ENCODING,
												RfbProtocol.RAW_ENCODING });

			await rfb.WriteSetPixelFormat(Framebuffer, ct);	// set the required ramebuffer format
            
			// Create an EncodedRectangleFactory so that EncodedRectangles can be built according to set pixel layout
			factory = new EncodedRectangleFactory(rfb, Framebuffer);
		}

		/// <summary>
		/// Begin getting updates from the VNC Server.  This will continue until StopUpdates() is called.  NOTE: this must be called after Connect().
		/// </summary>
		public void StartUpdates()
		{
            // Start getting updates on background thread.
            var tcs = new TaskCompletionSource<object>();
            worker = new Thread(
                () =>
                    {
                        try
                        {
                            this.GetRfbUpdates().Wait();
                            tcs.SetResult(null);
                        }
                        catch (Exception e)
                        {
                            tcs.SetException(e);
                        }
                    });
            // Bug Fix (Grégoire Pailler) for clipboard and threading
            worker.SetApartmentState(ApartmentState.STA);
            worker.IsBackground = true;
			done = new ManualResetEvent(false);
			worker.Start();
		}

		/// <summary>
		/// Stops sending requests for updates and disconnects from the remote host.  You must call Connect() again if you wish to re-establish a connection.
		/// </summary>
		public async Task Disconnect(CancellationToken ct = default)
		{
			// Stop the worker thread.
			if (done != null)
				done.Set();

			// BUG FIX: Simon.Phillips@warwick.ac.uk for UltraVNC disconnect issue
			// Request a tiny screen update to flush the blocking read
			try {
				await rfb.WriteFramebufferUpdateRequest(0, 0, 1, 1, false, ct);
			} catch {
				// this may not work, as Disconnect can get called in response to the
				// VncClient raising a ConnectionLost event (e.g., the remote host died).
			}
			if (worker != null)
				worker.Join(3000);	// this number is arbitrary, just so that it doesn't block forever....

			rfb.Close();	
			rfb = null;
		}

		/// <summary>
		/// An event that occurs whenever the server sends a Framebuffer Update.
		/// </summary>
		public event VncUpdateHandler VncUpdate;
		
		private bool CheckIfThreadDone()
		{
			return done.WaitOne(0, false);
		}
		
		/// <summary>
		/// Worker thread lives here and processes protocol messages infinitely, triggering events or other actions as necessary.
		/// </summary>
		private async Task GetRfbUpdates()
		{
			// Get the initial destkop from the host
			int connLostCount = 0;
			await RequestScreenUpdate(true);

			while (true) {
				if (CheckIfThreadDone())
					break;

                try {
                    // ReSharper disable once SwitchStatementMissingSomeCases
                    switch (await rfb.ReadServerMessageType()) {
                        case RfbProtocol.FRAMEBUFFER_UPDATE:
                            var rectangles = await rfb.ReadFramebufferUpdate();

                            if (CheckIfThreadDone())
                                break;

                            // TODO: consider gathering all update rectangles in a batch and *then* posting the event back to the main thread.
                            for (var i = 0; i < rectangles; ++i) {
                                // Get the update rectangle's info
                                var (rectangle, enc) = await rfb.ReadFramebufferUpdateRectHeader();

                                // Build a derived EncodedRectangle type and pull-down all the pixel info
                                var er = factory.Build(rectangle, enc);
                                await er.Decode();

                                // Let the UI know that an updated rectangle is available, but check
                                // to see if the user closed things down first.
                                if (CheckIfThreadDone() || VncUpdate == null) continue;
                                var e = new VncEventArgs(er);

                                // In order to play nicely with WinForms controls, we do a check here to 
                                // see if it is necessary to synchronize this event with the UI thread.
                                var control = VncUpdate.Target as Control;
                                if (control != null) {
                                    control.Invoke(VncUpdate, this, e);
                                } else {
                                    // Target is not a WinForms control, so do it on this thread...
                                    VncUpdate(this, new VncEventArgs(er));
                                }
                            }
                            break;
                        case RfbProtocol.BELL:
                            Beep();
                            break;
                        case RfbProtocol.SERVER_CUT_TEXT:
                            if (CheckIfThreadDone())
                                break;
                            // TODO: This is invasive, should there be a bool property allowing this message to be ignored?
                            Clipboard.SetDataObject((await rfb.ReadServerCutText()).Replace("\n", Environment.NewLine), true);
                            OnServerCutText();
                            break;
                        case RfbProtocol.SET_COLOUR_MAP_ENTRIES:
                            await rfb.ReadColourMapEntry();
                            break;
                    }
                    // Moved screen update request here to prevent it being called multiple times
                    // This was the case when multiple rectangles were returned by the host
                    await RequestScreenUpdate(FullScreenRefresh);
                    connLostCount = 0;
                    
                } catch
                {   // On the first time of no data being received we force a complete update
                    // This is for times when the server has no update, and caused the timeout.
                    if (connLostCount++ > 1)
                        OnConnectionLost();
                    else
                        await RequestScreenUpdate(true);
                }
                FullScreenRefresh = false;
            }
        }

	    private void OnConnectionLost()
		{
			// In order to play nicely with WinForms controls, we do a check here to 
			// see if it is necessary to synchronize this event with the UI thread.
		    if (!(ConnectionLost?.Target is Control)) return;
		    var target = (Control) ConnectionLost.Target;

		    if (target != null)
		        target.Invoke(ConnectionLost, this, EventArgs.Empty);
		    else
		        ConnectionLost(this, EventArgs.Empty);
		}

	    private void OnServerCutText()
        {
            // In order to play nicely with WinForms controls, we do a check here to 
            // see if it is necessary to synchronize this event with the UI thread.
            if (!(ServerCutText?.Target is Control)) return;
            var target = (Control) ServerCutText.Target;

            if (target != null)
                target.Invoke(ServerCutText, this, EventArgs.Empty);
            else
                ServerCutText(this, EventArgs.Empty);
        }

// There is no managed way to get a system beep (until Framework v.2.0). So depending on the platform, something external has to be called.
#if Win32
	    private static void Beep()
	    {
            SystemSounds.Beep.Play();
        }
#else
		private void Beep()	// bool just so it matches the NativeMethods API signature
		{
			// TODO: How to do this under Unix?
			System.Console.Write("Beep!");
			return true;
		}
#endif

        public async Task WriteClientCutText(string text)
        {
            try {
                await rfb.WriteClientCutText(text);
            } catch {
                OnConnectionLost();
            }
        }

		// TODO: This needs to be pushed into the protocol rather than expecting keysym from the caller.
		public void WriteKeyboardEvent(uint keysym, bool pressed)
		{
			try {
				inputPolicy.WriteKeyboardEvent(keysym, pressed);
			} catch {
				OnConnectionLost();
			}
		}

		// TODO: This needs to be pushed into the protocol rather than expecting the caller to create the mask.
		public void WritePointerEvent(byte buttonMask, Point point)
		{
			try {
				inputPolicy.WritePointerEvent(buttonMask, point);
			} catch {
    			OnConnectionLost();
			}
		}
		
		/// <summary>
		/// Requests that the remote host send a screen update.
		/// </summary>
		/// <param name="refreshFullScreen">TRUE if the entire screen should be refreshed, FALSE if only a partial region needs updating.</param>
		/// <remarks>RequestScreenUpdate needs to be called whenever the client screen needs to be updated to reflect the state of the remote 
		///	desktop.  Typically you only need to have a particular region of the screen updated and can still use the rest of the 
		/// pixels on the client-side (i.e., when moving the mouse pointer, only the area around the pointer changes).  Therefore, you should
		/// almost always set refreshFullScreen to FALSE.  If the client-side image becomes corrupted, call RequestScreenUpdate with
		/// refreshFullScreen set to TRUE to get the complete image sent again.
		/// </remarks>
		public async Task RequestScreenUpdate(bool refreshFullScreen)
		{
			try {
				await rfb.WriteFramebufferUpdateRequest(0, 0, (ushort) Framebuffer.Width, (ushort) Framebuffer.Height, !refreshFullScreen);
			} catch {
				OnConnectionLost();
			}
		}
	}
}