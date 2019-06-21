package com.thoughtworks.gocd.secretmanager.aws;

import com.amazonaws.auth.*;
import com.thoughtworks.gocd.secretmanager.aws.exceptions.AWSCredentialsException;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static com.thoughtworks.gocd.secretmanager.aws.AwsPlugin.LOGGER;
import static org.apache.commons.lang3.StringUtils.*;

public class AWSCredentialsProviderChain {
    private final List<AWSCredentialsProvider> credentialsProviders = new LinkedList<AWSCredentialsProvider>();

    public AWSCredentialsProviderChain() {
        this(new EnvironmentVariableCredentialsProvider(), new SystemPropertiesCredentialsProvider(), new InstanceProfileCredentialsProvider(false));
    }

    //used in test
    public AWSCredentialsProviderChain(AWSCredentialsProvider... awsCredentialsProviders) {
        credentialsProviders.addAll(Arrays.asList(awsCredentialsProviders));
    }

    private AWSStaticCredentialsProvider staticCredentialProvider(String accessKey, String secretKey) {
        if (isNoneBlank(accessKey, secretKey)) {
            return new AWSStaticCredentialsProvider(new BasicAWSCredentials(accessKey, secretKey));
        }

        if (isBlank(accessKey) && isNotBlank(secretKey)) {
            throw new AWSCredentialsException("Access key is mandatory if secret key is provided");
        }

        if (isNotBlank(accessKey) && isBlank(secretKey)) {
            throw new AWSCredentialsException("Secret key is mandatory if access key is provided");
        }
        return null;
    }

    public AWSCredentialsProvider getAWSCredentialsProvider(String accessKey, String secretKey) {
        final AWSStaticCredentialsProvider staticCredentialProvider = staticCredentialProvider(accessKey, secretKey);
        if (staticCredentialProvider != null) {
            credentialsProviders.add(0, staticCredentialProvider);
        }

        return autoDetectAWSCredentials();
    }

    public AWSCredentialsProvider autoDetectAWSCredentials() {
        for (AWSCredentialsProvider provider : credentialsProviders) {
            try {
                AWSCredentials credentials = provider.getCredentials();

                if (credentials.getAWSAccessKeyId() != null && credentials.getAWSSecretKey() != null) {
                    LOGGER.debug("Loading credentials from " + provider.toString());
                    return provider;
                }
            } catch (Exception e) {
                LOGGER.debug("Unable to load credentials from " + provider.toString() + ": " + e.getMessage());
            }
        }

        throw new AWSCredentialsException("Unable to load AWS credentials from any provider in the chain");
    }
}
