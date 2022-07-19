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

using System.Net;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Carcass.Core;
using NCredStash.Core.Settings;
using NCredStash.Core.Stores.Abstracts;

namespace NCredStash.Core.Stores;

public sealed class CredentialStore : ICredentialStore
{
    private readonly CredStashSettings _credStashSettings;
    private readonly IAmazonDynamoDB _amazonDynamoDb;

    public CredentialStore(CredStashSettings credStashSettings, IAmazonDynamoDB amazonDynamoDb)
    {
        ArgumentVerifier.NotNull(credStashSettings, nameof(credStashSettings));
        ArgumentVerifier.NotNull(amazonDynamoDb, nameof(amazonDynamoDb));

        _credStashSettings = credStashSettings;
        _amazonDynamoDb = amazonDynamoDb;
    }

    public async Task<Dictionary<string, string>> GetItemAsync(
        string key,
        CancellationToken cancellationToken = default
    )
    {
        cancellationToken.ThrowIfCancellationRequested();

        ArgumentVerifier.NotNull(key, nameof(key));

        QueryResponse queryResponse = await _amazonDynamoDb.QueryAsync(
            new QueryRequest
            {
                TableName = _credStashSettings.Table,
                Limit = 1,
                ScanIndexForward = false,
                ConsistentRead = true,
                KeyConditions = new Dictionary<string, Condition> {
                    {
                        _credStashSettings.Key,
                        new()
                        {
                            ComparisonOperator = ComparisonOperator.EQ,
                            AttributeValueList = new List<AttributeValue> { new(key) }
                        }
                    }
                }
            },
            cancellationToken
        );

        if (queryResponse.HttpStatusCode != HttpStatusCode.OK ||
            !queryResponse.Items.Any<Dictionary<string, AttributeValue>>()
        ) throw new InvalidOperationException($"Secret {key} not found.");

        return queryResponse.Items
            .First()
            .ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.S
            );
    }
}