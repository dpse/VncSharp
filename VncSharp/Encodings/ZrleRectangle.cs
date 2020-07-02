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
using System.Drawing;

namespace VncSharp.Encodings
{
    using System.Threading.Tasks;

    /// <summary>
	/// Implementation of ZRLE encoding, as well as drawing support. See RFB Protocol document v. 3.8 section 6.6.5.
	/// </summary>
	public sealed class ZrleRectangle : EncodedRectangle
	{
		private const int TILE_WIDTH = 64;
		private const int TILE_HEIGHT = 64;

		private readonly int[] palette = new int[128];
		private readonly int[] tileBuffer = new int[TILE_WIDTH * TILE_HEIGHT];

		public ZrleRectangle(RfbProtocol rfb, Framebuffer framebuffer, Rectangle rectangle)
			: base(rfb, framebuffer, rectangle, RfbProtocol.ZRLE_ENCODING)
		{
		}

		public override async Task Decode()
		{
			await rfb.ZrleReader.DecodeStream().ConfigureAwait(false);

			for (var ty = 0; ty < rectangle.Height; ty += TILE_HEIGHT) {
				var th = Math.Min(rectangle.Height - ty, TILE_HEIGHT);

				for (var tx = 0; tx < rectangle.Width; tx += TILE_WIDTH) {
					var tw = Math.Min(rectangle.Width - tx, TILE_WIDTH);

					var subencoding = await rfb.ZrleReader.ReadByteAsync().ConfigureAwait(false);

					if (subencoding >= 17 && subencoding <= 127 || subencoding == 129)
						throw new Exception("Invalid subencoding value");

					var isRLE = (subencoding & 128) != 0;
					var paletteSize = subencoding & 127;

					// Fill palette
					for (var i = 0; i < paletteSize; i++)
						palette[i] = await preader.ReadPixel().ConfigureAwait(false);

					if (paletteSize == 1) {
						// Solid tile
						FillRectangle(new Rectangle(tx, ty, tw, th), palette[0]);
						continue;
					}

					if (!isRLE) {
						if (paletteSize == 0) {
							// Raw pixel data
							await FillRectangle(new Rectangle(tx, ty, tw, th)).ConfigureAwait(false);
						} else {
							// Packed palette
							await ReadZrlePackedPixels(tw, th, palette, paletteSize, tileBuffer).ConfigureAwait(false);
							FillRectangle(new Rectangle(tx, ty, tw, th), tileBuffer);
						}
					} else {
						if (paletteSize == 0) {
							// Plain RLE
							await ReadZrlePlainRLEPixels(tw, th, tileBuffer).ConfigureAwait(false);
							FillRectangle(new Rectangle(tx, ty, tw, th), tileBuffer);
						} else {
							// Packed RLE palette
							await ReadZrlePackedRLEPixels(tx, ty, tw, th, palette, tileBuffer).ConfigureAwait(false);
							FillRectangle(new Rectangle(tx, ty, tw, th), tileBuffer);
						}
					}
				}
			}
		}
		
		private async Task ReadZrlePackedPixels(int tw, int th, int[] palette, int palSize, int[] tile)
		{
			var bppp = palSize > 16 ? 8 :
			    (palSize > 4 ? 4 : (palSize > 2 ? 2 : 1));
			var ptr = 0;

			for (var i = 0; i < th; i++) {
				var eol = ptr + tw;
				var b = 0;
				var nbits = 0;

				while (ptr < eol) {
					if (nbits == 0)	{
						b = await rfb.ZrleReader.ReadByteAsync().ConfigureAwait(false);
						nbits = 8;
					}
					nbits -= bppp;
					var index = (b >> nbits) & ((1 << bppp) - 1) & 127;
					tile[ptr++] = palette[index];
				}
			}
		}

		private async Task ReadZrlePlainRLEPixels(int tw, int th, int[] tileBuffer)
		{
			var ptr = 0;
			var end = ptr + tw * th;
			while (ptr < end) {
				var pix = await preader.ReadPixel().ConfigureAwait(false);
				var len = 1;
				int b;
				do {
					b = await rfb.ZrleReader.ReadByteAsync().ConfigureAwait(false);
					len += b;
				} while (b == byte.MaxValue);

				while (len-- > 0) tileBuffer[ptr++] = pix;
			}
		}

		private async Task ReadZrlePackedRLEPixels(int tx, int ty, int tw, int th, int[] palette, int[] tile)
		{
			var ptr = 0;
			var end = ptr + tw * th;
			while (ptr < end) {
				int index = await rfb.ZrleReader.ReadByteAsync().ConfigureAwait(false);
				var len = 1;
				if ((index & 128) != 0) {
					int b;
					do {
						b = await rfb.ZrleReader.ReadByteAsync().ConfigureAwait(false);
						len += b;
					} while (b == byte.MaxValue);
				}

				index &= 127;

				while (len-- > 0) tile[ptr++] = palette[index];
			}
		}
	}
}