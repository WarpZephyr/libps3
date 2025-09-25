using System;
using System.Buffers;

namespace libps3.Buffers
{
    internal readonly struct SecureBuffer<T> : IDisposable
    {
        private readonly T[] _buffer;
        private readonly int _length;

        internal readonly T[] Buffer
            => _buffer;

        internal readonly int Length
            => _length;

        internal readonly Span<T> Span
            => new Span<T>(_buffer, 0, _length);

        internal readonly ReadOnlySpan<T> ReadOnlySpan
            => new ReadOnlySpan<T>(_buffer, 0, _length);

        internal SecureBuffer(int length)
        {
            _buffer = ArrayPool<T>.Shared.Rent(length);
            _length = length;
        }

        internal SecureBuffer(ReadOnlySpan<T> source)
        {
            _buffer = ArrayPool<T>.Shared.Rent(source.Length);
            _length = source.Length;
            source.CopyTo(_buffer);
        }

        public void Dispose()
        {
            Array.Clear(_buffer, 0, _length);
            ArrayPool<T>.Shared.Return(_buffer);
        }
    }
}
