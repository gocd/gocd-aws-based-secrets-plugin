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

import com.amazonaws.secretsmanager.caching.SecretCache;
import com.amazonaws.secretsmanager.caching.SecretCacheConfiguration;
import com.google.gson.Gson;
import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

import java.net.URI;
import java.time.Instant;
import java.util.Map;

import static java.util.Collections.emptyMap;

public class SecretManagerClient {
    private final AWSCredentialsProviderChain awsCredentialsProviderChain;
    private final SecretCache secretCache;
    private final SecretsManagerClient awsSecretsManager;
    private volatile Instant lastUsed = Instant.now();

    public SecretManagerClient(SecretConfig secretConfig, AWSCredentialsProviderChain awsCredentialsProviderChain) {
        this.awsCredentialsProviderChain = awsCredentialsProviderChain;
        awsSecretsManager = getAwsSecretsManager(secretConfig);
        SecretCacheConfiguration secretCacheConfiguration = new SecretCacheConfiguration()
                .withClient(awsSecretsManager)
                .withPostQuantumTlsEnabled(false) // Explicitly disable for now as we will exclude the native CRT
                .withCacheItemTTL(secretConfig.getSecretCacheTTL());
        secretCache = new SecretCache(secretCacheConfiguration);
    }

    public Map<Object, Object> lookup(String secretId) {
        lastUsed = Instant.now();
        String secretString = secretCache.getSecretString(secretId);

        if (secretString != null && !secretString.isBlank()) {
            //noinspection unchecked
            return new Gson().fromJson(secretString, Map.class);
        }

        return emptyMap();
    }

    private SecretsManagerClient getAwsSecretsManager(SecretConfig secretConfig) {
        AwsCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider(secretConfig.getAwsAccessKey(), secretConfig.getAwsSecretAccessKey());
        return SecretsManagerClient.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.of(secretConfig.getRegion()))
                .endpointOverride(endpointUri(secretConfig.getAwsEndpoint()))
                .build();
    }

    private URI endpointUri(String endpoint) {
        URI uri = URI.create(endpoint);
        return uri.getScheme() == null ? URI.create("https://" + endpoint) : uri;
    }

    public Instant lastUsed() {
        return lastUsed;
    }

    public void close() {
        secretCache.close();
        awsSecretsManager.close();
    }
}
