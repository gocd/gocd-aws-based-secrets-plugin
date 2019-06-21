package com.thoughtworks.gocd.secretmanager.aws;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;

import java.util.HashMap;
import java.util.Map;

public class AWSClientFactory {
    private final Map<SecretConfig, AWSSecretsManager> secretManagerCache = new HashMap<>();
    private AWSCredentialsProviderChain awsCredentialsProviderChain;

    public AWSClientFactory(AWSCredentialsProviderChain awsCredentialsProviderChain) {
        this.awsCredentialsProviderChain = awsCredentialsProviderChain;
    }

    public AWSSecretsManager client(SecretConfig secretConfig) {
        if (secretManagerCache.containsKey(secretConfig)) {
            return secretManagerCache.get(secretConfig);
        }

        synchronized (secretManagerCache) {
            if (secretManagerCache.containsKey(secretConfig)) {
                return secretManagerCache.get(secretConfig);
            }

            AWSSecretsManager secretsManager = getAwsSecretsManager(secretConfig);
            secretManagerCache.put(secretConfig, secretsManager);
            return secretsManager;
        }
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
}
