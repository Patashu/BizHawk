﻿using System;
using System.Drawing;

namespace BizHawk.Client.EmuHawk.CustomControls
{
	public class GdiPlusRenderer : IControlRenderer
	{
		private Graphics _graphics;

		private readonly Pen _currentPen = new Pen(Color.Black);
		private readonly SolidBrush _currentBrush = new SolidBrush(Color.Black);
		private readonly SolidBrush _currentStringBrush = new SolidBrush(Color.Black);
		private Font _currentFont;
		private bool _rotateString;

		public GdiPlusRenderer(Font font)
		{
			_currentFont = font;
		}

		private class GdiPlusGraphicsLock : IDisposable
		{
			public void Dispose()
			{
				// Nothing to do
				// Other drawing methods need a way to dispose on demand, hence the need for 
				// this dummy class
			}
		}

		public void Dispose()
		{
			_currentPen.Dispose();
			_currentBrush.Dispose();
			_currentStringBrush.Dispose();
		}

		public void DrawBitmap(Bitmap bitmap, Point point)
		{
			_graphics.DrawImage(bitmap, point);
		}

		public void DrawRectangle(int nLeftRect, int nTopRect, int nRightRect, int nBottomRect)
		{
			_graphics.DrawRectangle(
				_currentPen,
				new Rectangle(nLeftRect, nTopRect, nRightRect - nLeftRect, nBottomRect - nTopRect));
		}

		public void DrawString(string str, Rectangle rect)
		{
			if (_rotateString)
			{
				_graphics.TranslateTransform(rect.X, rect.Y);
				_graphics.RotateTransform(90);
				_graphics.DrawString(str, _currentFont, _currentStringBrush, Point.Empty);
				_graphics.ResetTransform();
			}
			else
			{
				_graphics.DrawString(str, _currentFont, _currentStringBrush, rect);
			}
		}

		public void FillRectangle(int x, int y, int w, int h)
		{
			_graphics.FillRectangle(
				_currentBrush,
				new Rectangle(x, y, w, h));
		}

		public void Line(int x1, int y1, int x2, int y2)
		{
			_graphics.DrawLine(_currentPen, x1, y1, x2, y2);
		}

		public IDisposable LockGraphics(Graphics g, int width, int height)
		{
			_graphics = g;
			return new GdiPlusGraphicsLock();
		}

		public SizeF MeasureString(string str, Font font)
		{
			return _graphics.MeasureString(str, font);
		}

		public void PrepDrawString(Font font, Color color, bool rotate = false)
		{
			_currentFont = font;
			_currentStringBrush.Color = color;
			_rotateString = rotate;
		}

		public void SetBrush(Color color)
		{
			_currentBrush.Color = color;
		}

		public void SetSolidPen(Color color)
		{
			_currentPen.Color = color;
		}
	}
}
