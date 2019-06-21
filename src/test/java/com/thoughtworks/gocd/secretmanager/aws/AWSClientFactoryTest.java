package com.thoughtworks.gocd.secretmanager.aws;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

class AWSClientFactoryTest {
    @Mock
    private AWSCredentialsProviderChain credentialsProviderChain;
    private AWSClientFactory awsClientFactory;

    @BeforeEach
    void setUp() {
        initMocks(this);
        awsClientFactory = new AWSClientFactory(credentialsProviderChain);

        when(credentialsProviderChain.getAWSCredentialsProvider(anyString(), anyString())).thenReturn(mock(AWSCredentialsProvider.class));
    }

    @Test
    void shouldCreateAAWSSecretManagerForGivenSecretConfig() {
        SecretConfig secretConfig = mock(SecretConfig.class);
        when(secretConfig.getAwsEndpoint()).thenReturn("endpoint-url");

        AWSSecretsManager secretsManager = awsClientFactory.client(secretConfig);

        assertThat(secretsManager).isNotNull()
                .isInstanceOf(AWSSecretsManager.class);
    }

    @Test
    void shouldCreateDifferentManagerForDifferentSecretConfigs() {
        SecretConfig secretConfig1 = mock(SecretConfig.class);
        when(secretConfig1.getAwsEndpoint()).thenReturn("url-for-secret-config-1");
        SecretConfig secretConfig2 = mock(SecretConfig.class);
        when(secretConfig2.getAwsEndpoint()).thenReturn("url-for-secret-config-2");

        AWSSecretsManager secretsManager1 = awsClientFactory.client(secretConfig1);
        AWSSecretsManager secretsManager2 = awsClientFactory.client(secretConfig2);

        assertThat(secretsManager1).isNotEqualTo(secretsManager2);
    }

    @Test
    void shouldReturnManagerFromCacheForTheSameSecretConfig() {
        SecretConfig secretConfig = mock(SecretConfig.class);
        when(secretConfig.getAwsEndpoint()).thenReturn("endpoint-url");

        AWSSecretsManager firstManager = awsClientFactory.client(secretConfig);
        AWSSecretsManager managerFromSecondCall = awsClientFactory.client(secretConfig);

        assertThat(firstManager).isSameAs(managerFromSecondCall);
    }
}