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

import java.util.Map;

import static java.util.Collections.singletonList;
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

        when(credentialsProviderChain.getAWSCredentialsProvider(anyString(), anyString())).thenReturn(mock(AwsCredentialsProvider.class));
    }

    @Test
    void shouldCreateAAWSSecretManagerForGivenSecretConfig() {
        SecretConfig secretConfig = mock(SecretConfig.class);
        when(secretConfig.getAwsEndpoint()).thenReturn("endpoint-url");

        SecretManagerClient secretsManager = awsClientFactory.client(secretConfig);

        assertThat(secretsManager).isNotNull()
                .isInstanceOf(SecretManagerClient.class);
    }

    @Test
    void shouldCreateDifferentManagerForDifferentSecretConfigs() {
        SecretConfig secretConfig1 = mock(SecretConfig.class);
        when(secretConfig1.getAwsEndpoint()).thenReturn("url-for-secret-config-1");
        SecretConfig secretConfig2 = mock(SecretConfig.class);
        when(secretConfig2.getAwsEndpoint()).thenReturn("url-for-secret-config-2");

        SecretManagerClient secretsManager1 = awsClientFactory.client(secretConfig1);
        SecretManagerClient secretsManager2 = awsClientFactory.client(secretConfig2);

        assertThat(secretsManager1).isNotEqualTo(secretsManager2);
    }

    @Test
    void shouldReturnManagerFromCacheForTheSameSecretConfig() {
        SecretConfig secretConfig = mock(SecretConfig.class);
        when(secretConfig.getAwsEndpoint()).thenReturn("endpoint-url");

        SecretManagerClient firstManager = awsClientFactory.client(secretConfig);
        SecretManagerClient managerFromSecondCall = awsClientFactory.client(secretConfig);

        assertThat(firstManager).isSameAs(managerFromSecondCall);
    }

    @Test
    void shouldCloseAndClearAllExistingClientsInCache() {
        Map cache = mock(Map.class);
        SecretManagerClient client = mock(SecretManagerClient.class);
        AWSCredentialsProviderChain awsCredentialsProviderChain = mock(AWSCredentialsProviderChain.class);

        when(cache.values()).thenReturn(singletonList(client));

        new AWSClientFactory(awsCredentialsProviderChain, cache).client(new SecretConfig("end", "key", "secret"));

        verify(cache).clear();
        verify(client).close();
    }
}