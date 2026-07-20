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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static com.thoughtworks.gocd.secretmanager.aws.AWSClientFactory.MAX_IDLE_TIME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.openMocks;

class AWSClientFactoryTest {
    @Mock
    private AWSCredentialsProviderChain credentialsProviderChain;
    private AWSClientFactory awsClientFactory;

    @BeforeEach
    void setUp() {
        openMocks(this);
        awsClientFactory = new AWSClientFactory(credentialsProviderChain);

        when(credentialsProviderChain.getAWSCredentialsProvider(anyString(), anyString(), nullable(String.class), nullable(String.class))).thenReturn(mock(AwsCredentialsProvider.class));
    }

    @Test
    void shouldCreateAAWSSecretManagerForGivenSecretConfig() {
        SecretConfig secretConfig = new SecretConfig("https://endpoint-url", "key", "secret", "us-east-1");

        SecretManagerClient secretsManager = awsClientFactory.client(secretConfig);

        assertThat(secretsManager).isNotNull()
                .isInstanceOf(SecretManagerClient.class);
    }

    @Test
    void shouldDefaultToHttpsWhenEndpointHasNoScheme() {
        SecretConfig secretConfig = new SecretConfig("secretsmanager.us-east-1.amazonaws.com", "key", "secret", "us-east-1");

        SecretManagerClient secretsManager = awsClientFactory.client(secretConfig);

        assertThat(secretsManager).isNotNull()
                .isInstanceOf(SecretManagerClient.class);
    }

    @Test
    void shouldCreateDifferentManagerForDifferentSecretConfigs() {
        SecretConfig secretConfig1 = new SecretConfig("https://url-for-secret-config-1", "key", "secret", "us-east-1");
        SecretConfig secretConfig2 = new SecretConfig("https://url-for-secret-config-2", "key", "secret", "us-east-1");

        SecretManagerClient secretsManager1 = awsClientFactory.client(secretConfig1);
        SecretManagerClient secretsManager2 = awsClientFactory.client(secretConfig2);

        assertThat(secretsManager1).isNotEqualTo(secretsManager2);
    }

    @Test
    void shouldReturnManagerFromCacheForTheSameSecretConfig() {
        SecretConfig secretConfig = new SecretConfig("https://endpoint-url", "key", "secret", "us-east-1");

        SecretManagerClient firstManager = awsClientFactory.client(secretConfig);
        SecretManagerClient managerFromSecondCall = awsClientFactory.client(secretConfig);

        assertThat(firstManager).isSameAs(managerFromSecondCall);
    }

    @Test
    void shouldCloseAndEvictClientsIdleForLongerThanMaxIdleTime() {
        SecretManagerClient idleClient = mock(SecretManagerClient.class);
        when(idleClient.lastUsed()).thenReturn(Instant.now().minus(MAX_IDLE_TIME).minusSeconds(1));
        AWSCredentialsProviderChain awsCredentialsProviderChain = mock(AWSCredentialsProviderChain.class);

        ConcurrentMap<SecretConfig, SecretManagerClient> cache = new ConcurrentHashMap<>(
                Map.of(mock(SecretConfig.class), idleClient));

        SecretConfig newConfig = new SecretConfig("https://overridden.endpoint.example.com", "key", "secret", "us-east-1");
        SecretManagerClient newClient = new AWSClientFactory(awsCredentialsProviderChain, cache).client(newConfig);

        verify(idleClient).close();
        assertThat(cache).containsOnlyKeys(newConfig);
        assertThat(cache.get(newConfig)).isSameAs(newClient);
    }

    @Test
    void shouldRetainClientsUsedWithinMaxIdleTime() {
        SecretManagerClient recentClient = mock(SecretManagerClient.class);
        when(recentClient.lastUsed()).thenReturn(Instant.now());
        AWSCredentialsProviderChain awsCredentialsProviderChain = mock(AWSCredentialsProviderChain.class);

        SecretConfig recentConfig = mock(SecretConfig.class);
        ConcurrentMap<SecretConfig, SecretManagerClient> cache = new ConcurrentHashMap<>(
                Map.of(recentConfig, recentClient));

        SecretConfig newConfig = new SecretConfig("https://another.endpoint.example.com", "key", "secret", "us-east-1");
        new AWSClientFactory(awsCredentialsProviderChain, cache).client(newConfig);

        verify(recentClient, never()).close();
        assertThat(cache).containsOnlyKeys(recentConfig, newConfig);
    }

    @Test
    void shouldNotEvictTheRequestedClientEvenIfItHasBeenIdle() {
        SecretManagerClient idleButRequested = mock(SecretManagerClient.class);
        when(idleButRequested.lastUsed()).thenReturn(Instant.now().minus(MAX_IDLE_TIME).minusSeconds(1));
        AWSCredentialsProviderChain awsCredentialsProviderChain = mock(AWSCredentialsProviderChain.class);

        SecretConfig config = new SecretConfig("https://endpoint.example.com", "key", "secret", "us-east-1");
        ConcurrentMap<SecretConfig, SecretManagerClient> cache = new ConcurrentHashMap<>(Map.of(config, idleButRequested));

        SecretManagerClient returned = new AWSClientFactory(awsCredentialsProviderChain, cache).client(config);

        verify(idleButRequested, never()).close();
        assertThat(returned).isSameAs(idleButRequested);
        assertThat(cache).containsOnlyKeys(config);
    }
}