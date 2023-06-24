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

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.secretsmanager.caching.SecretCache;
import com.amazonaws.secretsmanager.caching.SecretCacheConfiguration;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.google.gson.Gson;
import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;

import java.util.Map;

import static java.util.Collections.emptyMap;

public class SecretManagerClient {
    private final AWSCredentialsProviderChain awsCredentialsProviderChain;
    private final SecretCache secretCache;
    private final AWSSecretsManager awsSecretsManager;

    public SecretManagerClient(SecretConfig secretConfig, AWSCredentialsProviderChain awsCredentialsProviderChain) {
        this.awsCredentialsProviderChain = awsCredentialsProviderChain;
        awsSecretsManager = getAwsSecretsManager(secretConfig);
        SecretCacheConfiguration secretCacheConfiguration = new SecretCacheConfiguration()
                .withClient(awsSecretsManager)
                .withCacheItemTTL(secretConfig.getSecretCacheTTL());
        secretCache = new SecretCache(secretCacheConfiguration);
    }

    public Map lookup(String secretId) {
        String secretString = secretCache.getSecretString(secretId);

        if (secretString != null && !secretString.isBlank()) {
            return new Gson().fromJson(secretString, Map.class);
        }

        return emptyMap();
    }

    private AWSSecretsManager getAwsSecretsManager(SecretConfig secretConfig) {
        AwsClientBuilder.EndpointConfiguration config = new AwsClientBuilder.EndpointConfiguration(secretConfig.getAwsEndpoint(), secretConfig.getRegion());
        AWSCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider(secretConfig.getAwsAccessKey(), secretConfig.getAwsSecretAccessKey());
        return AWSSecretsManagerClientBuilder
                .standard()
                .withCredentials(credentialsProvider)
                .withEndpointConfiguration(config)
                .build();
    }

    public void close() {
        secretCache.close();
        awsSecretsManager.shutdown();
    }
}
