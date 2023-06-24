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

import cd.go.plugin.base.executors.secrets.LookupExecutor;
import com.thoughtworks.go.plugin.api.logging.Logger;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.secretmanager.aws.models.Secrets;
import com.thoughtworks.gocd.secretmanager.aws.request.SecretConfigRequest;

import java.util.List;
import java.util.Map;

import static cd.go.plugin.base.GsonTransformer.fromJson;
import static cd.go.plugin.base.GsonTransformer.toJson;
import static java.lang.String.format;
import static java.util.Collections.singletonMap;

public class SecretConfigLookupExecutor extends LookupExecutor<SecretConfigRequest> {
    private static final Logger LOGGER = Logger.getLoggerFor(SecretConfigLookupExecutor.class);

    private AWSClientFactory awsClientFactory;

    public SecretConfigLookupExecutor() {
        this(new AWSClientFactory(new AWSCredentialsProviderChain()));
    }

    SecretConfigLookupExecutor(AWSClientFactory awsClientFactory) {
        this.awsClientFactory = awsClientFactory;
    }

    @Override
    protected GoPluginApiResponse execute(SecretConfigRequest request) {
        SecretManagerClient client;
        try {
            client = awsClientFactory.client(request.getConfiguration());

            List<String> secretIds = request.getKeys();

            if (secretIds == null || secretIds.isEmpty()) {
                return DefaultGoPluginApiResponse.badRequest("No secret key provided!!!");
            }

            Map result = client.lookup(request.getConfiguration().getSecretName());

            final Secrets secrets = new Secrets();

            secretIds.forEach(secretId -> {
                if (result.containsKey(secretId)) {
                    secrets.add(secretId, result.get(secretId).toString());
                }
            });

            return DefaultGoPluginApiResponse.success(toJson(secrets));
        } catch (Exception e) {
            LOGGER.error("Failed to lookup secret from AWS.", e);
            String errorMessage = format("Failed to lookup secrets from AWS - %s, See logs for more information.", e.getMessage());
            return DefaultGoPluginApiResponse.error(toJson(singletonMap("message", errorMessage)));
        }
    }

    @Override
    protected SecretConfigRequest parseRequest(String body) {
        return fromJson(body, SecretConfigRequest.class);
    }
}
