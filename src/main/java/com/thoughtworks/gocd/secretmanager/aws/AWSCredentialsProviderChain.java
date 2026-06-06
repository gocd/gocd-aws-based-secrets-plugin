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

import com.amazonaws.auth.*;
import com.thoughtworks.gocd.secretmanager.aws.exceptions.AWSCredentialsException;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static com.thoughtworks.gocd.secretmanager.aws.AwsPlugin.LOGGER;

public class AWSCredentialsProviderChain {
    private final List<AwsCredentialsProvider> credentialsProviders = new LinkedList<AwsCredentialsProvider>();

    public AWSCredentialsProviderChain() {
        this(EnvironmentVariableCredentialsProvider.create(), new SystemPropertiesCredentialsProvider(), InstanceProfileCredentialsProvider.create());
    }

    //used in test
    public AWSCredentialsProviderChain(AwsCredentialsProvider... awsCredentialsProviders) {
        credentialsProviders.addAll(Arrays.asList(awsCredentialsProviders));
    }

    private StaticCredentialsProvider staticCredentialProvider(String accessKey, String secretKey) {
        if (!isBlank(accessKey) && !isBlank(secretKey)) {
            return StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKey, secretKey));
        }

        if (isBlank(accessKey) && !isBlank(secretKey)) {
            throw new AWSCredentialsException("Access key is mandatory if secret key is provided");
        }

        if (!isBlank(accessKey) && isBlank(secretKey)) {
            throw new AWSCredentialsException("Secret key is mandatory if access key is provided");
        }
        return null;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public AwsCredentialsProvider getAWSCredentialsProvider(String accessKey, String secretKey) {
        final StaticCredentialsProvider staticCredentialProvider = staticCredentialProvider(accessKey, secretKey);
        if (staticCredentialProvider != null) {
            credentialsProviders.add(0, staticCredentialProvider);
        }

        return autoDetectAWSCredentials();
    }

    public AwsCredentialsProvider autoDetectAWSCredentials() {
        for (AwsCredentialsProvider provider : credentialsProviders) {
            try {
                AwsCredentials credentials = provider.resolveCredentials();

                if (credentials.accessKeyId() != null && credentials.secretAccessKey() != null) {
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
