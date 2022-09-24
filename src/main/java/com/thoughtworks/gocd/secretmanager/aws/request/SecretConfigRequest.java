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

package com.thoughtworks.gocd.secretmanager.aws.request;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;

import java.util.List;

public class SecretConfigRequest {
    @Expose
    @SerializedName("configuration")
    private SecretConfig configuration;

    @Expose
    @SerializedName("keys")
    private List<String> keys;

    public SecretConfigRequest() {
    }

    public SecretConfig getConfiguration() {
        return configuration;
    }

    public List<String> getKeys() {
        return keys;
    }
}
