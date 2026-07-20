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

import com.thoughtworks.gocd.secretmanager.aws.exceptions.AWSCredentialsException;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.utils.SdkAutoCloseable;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static com.thoughtworks.gocd.secretmanager.aws.AwsPlugin.LOGGER;

public class AWSCredentialsProviderChain {
    private static final String ROLE_SESSION_NAME = "gocd-aws-secrets-plugin";
    // Documented for use within sts:ExternalId trust policy conditions; changing the format breaks existing policies.
    public static final String EXTERNAL_ID_PREFIX = "gocd:server-id:";

    private final List<AwsCredentialsProvider> credentialsProviders;
    private final Supplier<String> serverIdSupplier;

    public AWSCredentialsProviderChain() {
        this(AwsPlugin::getServerId, EnvironmentVariableCredentialsProvider.create(), SystemPropertyCredentialsProvider.create(), InstanceProfileCredentialsProvider.builder().asyncCredentialUpdateEnabled(false).build());
    }

    //used in test
    public AWSCredentialsProviderChain(AwsCredentialsProvider... awsCredentialsProviders) {
        this(AwsPlugin::getServerId, awsCredentialsProviders);
    }

    //used in test
    public AWSCredentialsProviderChain(Supplier<String> serverIdSupplier, AwsCredentialsProvider... awsCredentialsProviders) {
        this.serverIdSupplier = serverIdSupplier;
        this.credentialsProviders = List.of(awsCredentialsProviders);
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
        return getAWSCredentialsProvider(accessKey, secretKey, null, null);
    }

    public AwsCredentialsProvider getAWSCredentialsProvider(String accessKey, String secretKey, String assumeRoleArn, String region) {
        AwsCredentialsProvider provider = getAwsCredentialsProviderFrom(Stream.concat(
                Stream.ofNullable(staticCredentialProvider(accessKey, secretKey)),
                credentialsProviders.stream()).toList()
        );
        return withAssumedRoleIfConfigured(provider, assumeRoleArn, region);
    }

    public AwsCredentialsProvider autoDetectAWSCredentials() {
        return getAwsCredentialsProviderFrom(credentialsProviders);
    }

    private AwsCredentialsProvider getAwsCredentialsProviderFrom(List<AwsCredentialsProvider> credentialsProviders) {
        for (AwsCredentialsProvider provider : credentialsProviders) {
            try {
                AwsCredentials credentials = provider.resolveCredentials();

                if (credentials.accessKeyId() != null && credentials.secretAccessKey() != null) {
                    LOGGER.debug("Loading credentials from " + provider);
                    return provider;
                }
            } catch (Exception e) {
                LOGGER.debug("Unable to load credentials from " + provider.toString() + ": " + e.getMessage());
            }
        }

        throw new AWSCredentialsException("Unable to load AWS credentials from any provider in the chain");
    }

    private AwsCredentialsProvider withAssumedRoleIfConfigured(AwsCredentialsProvider provider, String assumeRoleArn, String region) {
        if (isBlank(assumeRoleArn)) {
            return provider;
        }

        LOGGER.debug("Assuming role " + assumeRoleArn + " using credentials from " + provider);
        final StsClientBuilder stsClientBuilder = StsClient.builder().credentialsProvider(provider);
        if (!isBlank(region)) {
            stsClientBuilder.region(Region.of(region));
        }
        final StsClient stsClient = stsClientBuilder.build();
        final StsAssumeRoleCredentialsProvider assumeRoleProvider = StsAssumeRoleCredentialsProvider.builder()
                .asyncCredentialUpdateEnabled(false)
                .stsClient(stsClient)
                .refreshRequest(AssumeRoleRequest.builder()
                        .roleArn(assumeRoleArn)
                        .roleSessionName(ROLE_SESSION_NAME)
                        .externalId(externalId())
                        .build())
                .build();
        return new AssumeRoleProviderOwningStsClient(assumeRoleProvider, stsClient);
    }

    String externalId() {
        final String serverId = serverIdSupplier.get();
        return isBlank(serverId) ? null : EXTERNAL_ID_PREFIX + serverId;
    }

    /**
     * StsAssumeRoleCredentialsProvider.close() does not close a caller-supplied StsClient, so this wrapper takes
     * ownership of both; callers that close the returned provider release every underlying resource.
     */
    record AssumeRoleProviderOwningStsClient(StsAssumeRoleCredentialsProvider delegate,
                                             StsClient stsClient) implements AwsCredentialsProvider, SdkAutoCloseable {
        @Override
        public AwsCredentials resolveCredentials() {
            return delegate.resolveCredentials();
        }

        @Override
        public void close() {
            delegate.close();
            stsClient.close();
        }
    }
}
