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

import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;
import com.thoughtworks.gocd.secretmanager.aws.request.SecretConfigRequest;
import org.json.JSONException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.skyscreamer.jsonassert.JSONAssert.assertEquals;

class SecretConfigLookupExecutorTest {
    private SecretConfigRequest request;
    @Mock
    private AWSClientFactory clientFactory;
    @Mock
    private SecretManagerClient secretsManager;
    private SecretConfigLookupExecutor secretConfigLookupExecutor;

    @BeforeEach
    void setUp() {
        openMocks(this);
        request = mock(SecretConfigRequest.class);
        secretConfigLookupExecutor = new SecretConfigLookupExecutor(clientFactory);
    }

    @Test
    void shouldReturnLookupResponseForSingleKey() throws JSONException {
        SecretConfig secretConfig = mock(SecretConfig.class);

        when(request.getKeys()).thenReturn(singletonList("key1"));
        when(request.getConfiguration()).thenReturn(secretConfig);
        when(secretConfig.getSecretName()).thenReturn("secret_id");
        when(clientFactory.client(secretConfig)).thenReturn(secretsManager);
        when(secretsManager.lookup(any(String.class))).thenReturn(Map.of("key1", "value1"));

        final GoPluginApiResponse response = secretConfigLookupExecutor.execute(request);

        assertThat(response.responseCode()).isEqualTo(200);
        final String expectedResponse = "[{\"key\":\"key1\",\"value\":\"value1\"}]";
        assertEquals(expectedResponse, response.responseBody(), true);
    }

    @Test
    void shouldReturnLookupResponseForMultipleKeys() throws JSONException {
        List<String> requestIds = Arrays.asList("key1", "key2");
        SecretConfig secretConfig = mock(SecretConfig.class);

        when(request.getKeys()).thenReturn(requestIds);
        when(request.getConfiguration()).thenReturn(secretConfig);
        when(secretConfig.getSecretName()).thenReturn("secret_id");
        when(clientFactory.client(secretConfig)).thenReturn(secretsManager);
        Map<Object, Object> secrets = new HashMap<>();
        secrets.put("key1", "value1");
        secrets.put("key2", "value2");
        when(secretsManager.lookup(any(String.class))).thenReturn(secrets);

        final GoPluginApiResponse response = secretConfigLookupExecutor.execute(request);

        assertThat(response.responseCode()).isEqualTo(200);
        final String expectedResponse = "[{\"key\":\"key1\",\"value\":\"value1\"},{\"key\":\"key2\",\"value\":\"value2\"}]";
        assertEquals(expectedResponse, response.responseBody(), true);
    }

    @Test
    void shouldReturnAErrorResponseIfLookupFails() throws JSONException {
        SecretConfig secretConfig = mock(SecretConfig.class);

        when(request.getKeys()).thenReturn(singletonList("key1"));
        when(request.getConfiguration()).thenReturn(secretConfig);
        when(secretConfig.getSecretName()).thenReturn("secret_id");
        when(clientFactory.client(secretConfig)).thenReturn(secretsManager);
        when(secretsManager.lookup(any(String.class))).thenThrow(new RuntimeException("error"));

        final GoPluginApiResponse response = secretConfigLookupExecutor.execute(request);

        assertThat(response.responseCode()).isEqualTo(500);
        assertThat(response.responseBody()).isEqualTo("{\"message\":\"Failed to lookup secrets from AWS - error, See logs for more information.\"}");
    }
}