package com.thoughtworks.gocd.secretmanager.aws.validators;

import com.github.bdpiparva.plugin.base.validation.ValidationResult;
import com.thoughtworks.gocd.secretmanager.aws.annotations.JsonSource;
import com.thoughtworks.gocd.secretmanager.aws.extensions.EnvironmentVariable;
import com.thoughtworks.gocd.secretmanager.aws.extensions.SystemProperty;
import org.json.JSONException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.HashMap;
import java.util.Map;

import static com.amazonaws.SDKGlobalConfiguration.*;
import static com.github.bdpiparva.plugin.base.GsonTransformer.toJson;
import static com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig.ACCESS_KEY;
import static com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig.SECRET_ACCESS_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.skyscreamer.jsonassert.JSONAssert.assertEquals;

class CredentialValidatorTest {
    private CredentialValidator credentialValidator;

    @BeforeEach
    void setUp() {
        credentialValidator = new CredentialValidator();
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