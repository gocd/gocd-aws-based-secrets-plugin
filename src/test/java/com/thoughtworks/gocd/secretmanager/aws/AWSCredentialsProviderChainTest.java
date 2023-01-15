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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import static com.amazonaws.SDKGlobalConfiguration.*;
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
        awsCredentialsProviderChain = new AWSCredentialsProviderChain(new EnvironmentVariableCredentialsProvider(), new SystemPropertiesCredentialsProvider());
    }

    @Test
    void shouldUseAccessKeyAndSecretKeyAsACredentialsIfProvided() {
        final AWSCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider("access-key", "secret-key");

        assertThat(credentialsProvider).isInstanceOf(AWSStaticCredentialsProvider.class);

        final AWSCredentials credentials = credentialsProvider.getCredentials();
        assertThat(credentials.getAWSAccessKeyId()).isEqualTo("access-key");
        assertThat(credentials.getAWSSecretKey()).isEqualTo("secret-key");
    }

    @Test
    void shouldReadCredentialsFromEnvironmentIfNotProvidedInMethodCall() {
        env.set(SECRET_KEY_ENV_VAR, "secret-key-from-env");
        env.set(ACCESS_KEY_ENV_VAR, "access-key-from-env");
        final AWSCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider(null, null);
        assertThat(credentialsProvider).isInstanceOf(EnvironmentVariableCredentialsProvider.class);

        final AWSCredentials credentials = credentialsProvider.getCredentials();
        assertThat(credentials.getAWSAccessKeyId()).isEqualTo("access-key-from-env");
        assertThat(credentials.getAWSSecretKey()).isEqualTo("secret-key-from-env");
    }

    @Test
    void shouldReadCredentialsFromSystemPropertiesWhenEnvCredentialsAreNotProvided() {
        systemProperties.set(ACCESS_KEY_SYSTEM_PROPERTY, "access-key-from-system-prop");
        systemProperties.set(SECRET_KEY_SYSTEM_PROPERTY, "secret-key-from-system-prop");
        final AWSCredentialsProvider credentialsProvider = awsCredentialsProviderChain.getAWSCredentialsProvider(null, null);
        assertThat(credentialsProvider).isInstanceOf(SystemPropertiesCredentialsProvider.class);

        final AWSCredentials credentials = credentialsProvider.getCredentials();
        assertThat(credentials.getAWSAccessKeyId()).isEqualTo("access-key-from-system-prop");
        assertThat(credentials.getAWSSecretKey()).isEqualTo("secret-key-from-system-prop");
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