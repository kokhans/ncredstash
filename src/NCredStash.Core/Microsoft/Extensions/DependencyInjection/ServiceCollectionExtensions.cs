﻿// MIT License
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

using Carcass.Core;
using NCredStash.Core.Decrypters;
using NCredStash.Core.Decrypters.Abstracts;
using NCredStash.Core.HmacVerifiers;
using NCredStash.Core.HmacVerifiers.Abstracts;
using NCredStash.Core.Providers;
using NCredStash.Core.Providers.Abstracts;
using NCredStash.Core.Settings;
using NCredStash.Core.Stores.Abstracts;

// ReSharper disable CheckNamespace

namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddNCredStash(
        this IServiceCollection services,
        CredStashSettings? credStashSettings = default
    )
    {
        ArgumentVerifier.NotNull(services, nameof(services));

        return services
            .AddSingleton(credStashSettings ?? CredStashSettings.Defaults())
            .AddSingleton<ICredentialStore, ICredentialStore>()
            .AddSingleton<IMasterKeyStore, IMasterKeyStore>()
            .AddSingleton<IDecrypter, AesDecrypter>()
            .AddSingleton<IHmacVerifier, Sha256HmacVerifier>()
            .AddSingleton<ICredStashProvider, CredStashProvider>();
    }
}