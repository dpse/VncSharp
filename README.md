# VncSharp

This a fork of [VncSharp](https://github.com/humphd/VncSharp) that adds support for asynchronous connection operations. This makes it possible to use the `RemoteDesktop` control without blocking the UI thread. Just await `ConnectAsync` rather than calling `Connect`. It as also possible to connect through a `Stream`, which makes it possibly to easily route traffic through e.g. a proxy server.

The implementation makes use of the `AsyncBinaryReader` and `AsyncBinaryWriter` implementations from [AsyncBinaryReaderWriter](https://github.com/ronnieoverby/AsyncBinaryReaderWriter).

VncSharp is a Free and Open Source (GPL) implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework. Virtual Network Computing (VNC) is a cross-platform client/server protocol allowing remote systems to be controlled over a network. VncSharp is a VNC Client Library and custom Windows Forms Control. VncSharp is also Free Software, released under the GPL. You can freely use VncSharp to bundle VNC functionality into your own .NET applications simply by dragging and dropping a control onto your form.
