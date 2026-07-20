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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.core.SdkSystemSetting;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

@ExtendWith(SystemStubsExtension.class)
class AWSCredentialsProviderChainTest {

    @SystemStub
    private SystemProperties systemProperties;

    @SystemStub
    private EnvironmentVariables env;

    private AWSCredentialsProviderChain awsCredentialsProviderChain;

    @BeforeEach
    void setUp() {
        awsCredentialsProviderChain = new AWSCredentialsProviderChain(EnvironmentVariableCredentialsProvider.create(), SystemPropertyCredentialsProvider.create());

        env.remove(SdkSystemSetting.AWS_SECRET_ACCESS_KEY.environmentVariable());
        env.remove(SdkSystemSetting.AWS_ACCESS_KEY_ID.environmentVariable());
        systemProperties.remove(SdkSystemSetting.AWS_SECRET_ACCESS_KEY.property());
        systemProperties.remove(SdkSystemSetting.AWS_ACCESS_KEY_ID.property());
    }

    @Test
    void shouldUseAccessKeyAndSecretKeyAsACredentialsIfProvided() {
        final AwsCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider("access-key", "secret-key");

        assertThat(credentialsProvider).isInstanceOf(StaticCredentialsProvider.class);

        final AwsCredentials credentials = credentialsProvider.resolveCredentials();
        assertThat(credentials.accessKeyId()).isEqualTo("access-key");
        assertThat(credentials.secretAccessKey()).isEqualTo("secret-key");
    }

    @Test
    void shouldNotWrapWithAssumeRoleProviderWhenAssumeRoleArnIsBlank() {
        final AwsCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider("access-key", "secret-key", "  ", "us-east-1");

        assertThat(credentialsProvider).isInstanceOf(StaticCredentialsProvider.class);
    }

    @Test
    void shouldWrapWithAssumeRoleProviderWhenAssumeRoleArnIsProvided() {
        final AwsCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider("access-key", "secret-key", "arn:aws:iam::123456789012:role/some-role", "us-east-1");

        assertThat(credentialsProvider).isInstanceOf(AWSCredentialsProviderChain.AssumeRoleProviderOwningStsClient.class);
    }

    @Test
    void shouldDeriveExternalIdFromGoCDServerId() {
        assertThat(new AWSCredentialsProviderChain(() -> "some-server-id").externalId()).isEqualTo("gocd:server-id:some-server-id");
    }

    @Test
    void shouldHaveNoExternalIdWhenServerIdIsNotAvailable() {
        assertThat(new AWSCredentialsProviderChain(() -> (String) null).externalId()).isNull();
        assertThat(new AWSCredentialsProviderChain(() -> " ").externalId()).isNull();
    }

    @Test
    void shouldReadCredentialsFromEnvironmentIfNotProvidedInMethodCall() {
        env.set(SdkSystemSetting.AWS_SECRET_ACCESS_KEY.environmentVariable(), "secret-key-from-env");
        env.set(SdkSystemSetting.AWS_ACCESS_KEY_ID.environmentVariable(), "access-key-from-env");
        final AwsCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider(null, null);
        assertThat(credentialsProvider).isInstanceOf(EnvironmentVariableCredentialsProvider.class);

        final AwsCredentials credentials = credentialsProvider.resolveCredentials();
        assertThat(credentials.accessKeyId()).isEqualTo("access-key-from-env");
        assertThat(credentials.secretAccessKey()).isEqualTo("secret-key-from-env");
    }

    @Test
    void shouldReadCredentialsFromSystemPropertiesWhenEnvCredentialsAreNotProvided() {
        systemProperties.set(SdkSystemSetting.AWS_ACCESS_KEY_ID.property(), "access-key-from-system-prop");
        systemProperties.set(SdkSystemSetting.AWS_SECRET_ACCESS_KEY.property(), "secret-key-from-system-prop");
        final AwsCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider(null, null);
        assertThat(credentialsProvider).isInstanceOf(SystemPropertyCredentialsProvider.class);

        final AwsCredentials credentials = credentialsProvider.resolveCredentials();
        assertThat(credentials.accessKeyId()).isEqualTo("access-key-from-system-prop");
        assertThat(credentials.secretAccessKey()).isEqualTo("secret-key-from-system-prop");
    }

    @Test
    void shouldErrorOutIfItFailsToLoadCredentials() {
        try {
            awsCredentialsProviderChain.getAWSCredentialsProvider(null, null);
            fail("should fail");
        } catch (AWSCredentialsException e) {
            assertThat(e.getMessage()).isEqualTo("Unable to load AWS credentials from any provider in the chain");
        }
    }

    @Test
    void shouldErrorOutIfOnlyAccessKeyIsProvided() {
        try {
            awsCredentialsProviderChain.getAWSCredentialsProvider("access-key", null);
            fail("should fail");
        } catch (AWSCredentialsException e) {
            assertThat(e.getMessage()).isEqualTo("Secret key is mandatory if access key is provided");
        }
    }

    @Test
    void shouldErrorOutIfOnlySecretKeyIsProvided() {
        try {
            awsCredentialsProviderChain.getAWSCredentialsProvider(null, "secret-key");
            fail("should fail");
        } catch (AWSCredentialsException e) {
            assertThat(e.getMessage()).isEqualTo("Access key is mandatory if secret key is provided");
        }
    }

}