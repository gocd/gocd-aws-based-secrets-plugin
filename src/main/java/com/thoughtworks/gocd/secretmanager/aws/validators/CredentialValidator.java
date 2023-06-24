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

import cd.go.plugin.base.GsonTransformer;
import cd.go.plugin.base.validation.ValidationResult;
import cd.go.plugin.base.validation.Validator;
import com.thoughtworks.go.plugin.api.logging.Logger;
import com.thoughtworks.gocd.secretmanager.aws.AWSCredentialsProviderChain;
import com.thoughtworks.gocd.secretmanager.aws.exceptions.AWSCredentialsException;
import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;

import java.util.Map;

import static com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig.ACCESS_KEY;
import static com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig.SECRET_ACCESS_KEY;

public class CredentialValidator implements Validator {
    private static final Logger LOGGER = Logger.getLoggerFor(CredentialValidator.class);
    private final AWSCredentialsProviderChain credentialsProviderChain;

    public CredentialValidator() {
        this(new AWSCredentialsProviderChain());
    }

    CredentialValidator(AWSCredentialsProviderChain credentialsProviderChain) {
        this.credentialsProviderChain = credentialsProviderChain;
    }

    @Override
    public ValidationResult validate(Map<String, String> requestBody) {
        ValidationResult validationResult = new ValidationResult();
        try {
            credentialsProviderChain.autoDetectAWSCredentials();
            return validationResult;
        } catch (AWSCredentialsException e) {
            LOGGER.info(e.getMessage());
        }

        SecretConfig secretConfig = GsonTransformer.fromJson(GsonTransformer.toJson(requestBody), SecretConfig.class);

        if (isBlank(secretConfig.getAwsAccessKey())) {
            validationResult.add(ACCESS_KEY, "Must not be blank.");
        }

        if (isBlank(secretConfig.getAwsSecretAccessKey())) {
            validationResult.add(SECRET_ACCESS_KEY, "Must not be blank.");
        }

        return validationResult;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
