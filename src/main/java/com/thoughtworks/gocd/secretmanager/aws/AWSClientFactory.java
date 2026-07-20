/*
 * Copyright 2022 Thoughtworks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.thoughtworks.gocd.secretmanager.aws;

import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class AWSClientFactory {
    // Each client owns an LRU+TTL SecretCache that already self-bounds its cached secrets, so eviction exists
    // only to release the SDK client (connection pool) for SecretConfigs that are no longer in use at all -
    // e.g. after an admin edits or removes a config. We keep this window well above the secret cache item TTL
    // (30 min by default) so that a config still in periodic use keeps its warm cache rather than being rebuilt cold.
    static final Duration MAX_IDLE_TIME = Duration.ofHours(6);

    private final ConcurrentMap<SecretConfig, SecretManagerClient> secretManagerCache;
    private final AWSCredentialsProviderChain awsCredentialsProviderChain;

    public AWSClientFactory(AWSCredentialsProviderChain awsCredentialsProviderChain) {
        this(awsCredentialsProviderChain, new ConcurrentHashMap<>());
    }

    protected AWSClientFactory(AWSCredentialsProviderChain awsCredentialsProviderChain, ConcurrentMap<SecretConfig, SecretManagerClient> cache) {
        this.awsCredentialsProviderChain = awsCredentialsProviderChain;
        this.secretManagerCache = cache;
    }

    public SecretManagerClient client(SecretConfig secretConfig) {
        SecretManagerClient client = secretManagerCache.computeIfAbsent(secretConfig, config -> new SecretManagerClient(config, awsCredentialsProviderChain));
        closeIdleClientsExcept(secretConfig);
        return client;
    }

    /*
    * Since there is no mechanism to know when a SecretConfig is no longer in use, we close and evict any client
    * that has not been used within MAX_IDLE_TIME. The client just obtained by the caller is excluded so it is never
    * evicted mid-request - the caller has not had a chance to lookup() (which refreshes lastUsed) yet.
    * */
    private void closeIdleClientsExcept(SecretConfig current) {
        Instant cutoff = Instant.now().minus(MAX_IDLE_TIME);
        secretManagerCache.forEach((key, value) -> {
            if (!current.equals(key) && value.lastUsed().isBefore(cutoff)) {
                secretManagerCache.compute(key, (k, existing) -> {
                    if (existing != null && existing.lastUsed().isBefore(cutoff)) {
                        existing.close();
                        return null;
                    }
                    return existing;
                });
            }
        });
    }
}
