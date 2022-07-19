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

using System.Text;
using Carcass.Core;
using NCredStash.Core.Decrypters.Abstracts;
using NCredStash.Core.HmacVerifiers.Abstracts;
using NCredStash.Core.Providers.Abstracts;
using NCredStash.Core.Stores.Abstracts;

namespace NCredStash.Core.Providers;

public sealed class CredStashProvider : ICredStashProvider
{
    private readonly ICredentialStore _credentialStore;
    private readonly IMasterKeyStore _masterKeyStore;
    private readonly IDecrypter _decrypter;
    private readonly IHmacVerifier _hmacVerifier;

    public CredStashProvider(
        ICredentialStore credentialStore,
        IMasterKeyStore masterKeyStore,
        IDecrypter decrypter,
        IHmacVerifier hmacVerifier
    )
    {
        ArgumentVerifier.NotNull(credentialStore, nameof(credentialStore));
        ArgumentVerifier.NotNull(masterKeyStore, nameof(masterKeyStore));
        ArgumentVerifier.NotNull(decrypter, nameof(decrypter));
        ArgumentVerifier.NotNull(hmacVerifier, nameof(hmacVerifier));

        _credentialStore = credentialStore;
        _masterKeyStore = masterKeyStore;
        _decrypter = decrypter;
        _hmacVerifier = hmacVerifier;
    }

    public async Task<string> GetSecretAsync(
        string key,
        Dictionary<string, string> encryptionContext,
        CancellationToken cancellationToken = default
    )
    {
        cancellationToken.ThrowIfCancellationRequested();

        ArgumentVerifier.NotNull(key, nameof(key));
        ArgumentVerifier.NotNull(encryptionContext, nameof(encryptionContext));

        Dictionary<string, string> item = await _credentialStore.GetItemAsync(key, cancellationToken);

        byte[] sourceBuffer = await _masterKeyStore.DecryptAsync(
            Convert.FromBase64String(item[nameof(key)]),
            encryptionContext,
            cancellationToken
        );

        byte[] destinationBuffer = new byte[32];
        Buffer.BlockCopy(sourceBuffer, 32, destinationBuffer, 0, 32);
        _hmacVerifier.Verify(
            destinationBuffer,
            Convert.FromBase64String(item["contents"]), item["hmac"]
        );

        return Encoding.UTF8.GetString(
            _decrypter.Decrypt(
                destinationBuffer,
                Convert.FromBase64String(item["contents"])
            )
        );
    }


}