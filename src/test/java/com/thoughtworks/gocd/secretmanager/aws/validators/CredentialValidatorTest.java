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

package com.thoughtworks.gocd.secretmanager.aws.validators;

import cd.go.plugin.base.validation.ValidationResult;
import com.thoughtworks.gocd.secretmanager.aws.AWSCredentialsProviderChain;
import com.thoughtworks.gocd.secretmanager.aws.annotations.JsonSource;
import com.thoughtworks.gocd.secretmanager.aws.exceptions.AWSCredentialsException;
import com.thoughtworks.gocd.secretmanager.aws.extensions.EnvironmentVariable;
import com.thoughtworks.gocd.secretmanager.aws.extensions.SystemProperty;
import org.json.JSONException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.mockito.Mock;

import java.util.HashMap;
import java.util.Map;

import static cd.go.plugin.base.GsonTransformer.toJson;
import static com.amazonaws.SDKGlobalConfiguration.*;
import static com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig.ACCESS_KEY;
import static com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig.SECRET_ACCESS_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.skyscreamer.jsonassert.JSONAssert.assertEquals;

class CredentialValidatorTest {
    @Mock
    private AWSCredentialsProviderChain credentialsProviderChain;
    private CredentialValidator credentialValidator;

    @BeforeEach
    void setUp() {
        initMocks(this);
        credentialValidator = new CredentialValidator(credentialsProviderChain);
    }

    @Test
    void shouldBeValidIfCredentialsAreProvidedInSecretConfig() {
        ValidationResult result = credentialValidator.validate(secretConfig("access-key", "secret-access-key"));

        assertThat(result.isEmpty()).isTrue();
    }

    @Test
    @EnvironmentVariable(key = ACCESS_KEY_ENV_VAR, value = "access-key-from-env")
    @EnvironmentVariable(key = SECRET_KEY_ENV_VAR, value = "secret-key-from-env")
    void shouldBeValidIfCredentialsAreProvidedAsEnvironmentVariable() {
        ValidationResult result = credentialValidator.validate(secretConfig(null, null));

        assertThat(result.isEmpty()).isTrue();
    }

    @Test
    @SystemProperty(key = ACCESS_KEY_SYSTEM_PROPERTY, value = "access-key-from-system-prop")
    @SystemProperty(key = SECRET_KEY_SYSTEM_PROPERTY, value = "secret-key-from-system-prop")
    void shouldBeValidIfCredentialsAreProvidedAsSystemProperties() {
        ValidationResult result = credentialValidator.validate(secretConfig(null, null));

        assertThat(result.isEmpty()).isTrue();
    }

    @ParameterizedTest
    @JsonSource(jsonFiles = "/missing-credentials-validation-error.json")
    void shouldBeInvalidWhenCredentialsAreNotProvidedAndFailsToDetectItUsingCredentialProviders(String expectedJson) throws JSONException {
        when(credentialsProviderChain.autoDetectAWSCredentials()).thenThrow(new AWSCredentialsException("Boom!"));

        ValidationResult result = credentialValidator.validate(secretConfig(null, null));

        assertThat(result.isEmpty()).isFalse();
        assertEquals(expectedJson, toJson(result), true);
    }

    private Map<String, String> secretConfig(String accessKey, String secretAccessKey) {
        Map<String, String> secretConfigMap = new HashMap<>();
        secretConfigMap.put(ACCESS_KEY, accessKey);
        secretConfigMap.put(SECRET_ACCESS_KEY, secretAccessKey);
        return secretConfigMap;
    }
}
