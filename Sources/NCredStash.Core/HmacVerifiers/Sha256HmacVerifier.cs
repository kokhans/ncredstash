// MIT License
//
// Copyright (c) 2022 Serhii Kokhan
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

using System.Security.Cryptography;
using Carcass.Core;
using NCredStash.Core.HmacVerifiers.Abstracts;

namespace NCredStash.Core.HmacVerifiers;

public sealed class Sha256HmacVerifier : IHmacVerifier
{
    public void Verify(byte[] hmacKeyBytes, byte[] contentsBytes, string storedHmac)
    {
        ArgumentVerifier.NotNull(hmacKeyBytes, nameof(hmacKeyBytes));
        ArgumentVerifier.NotNull(contentsBytes, nameof(contentsBytes));
        ArgumentVerifier.NotNull(storedHmac, nameof(storedHmac));

        string computedHmac = BitConverter
            .ToString(new HMACSHA256(hmacKeyBytes).ComputeHash(contentsBytes))
            .Replace("-", string.Empty)
            .ToLower();

        if (computedHmac != storedHmac)
            throw new InvalidOperationException("Computed HMAC does not match stored HMAC.");
    }
}