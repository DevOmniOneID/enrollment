/*
 * Copyright 2025 OmniOne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.oid4vc.enrollment.core.enroll;

import com.example.oid4vc.enrollment.core.crypto.CryptoProvider;
import com.example.oid4vc.enrollment.core.entity.EntityProvider;
import com.example.oid4vc.enrollment.core.transport.DefaultTransportProvider;
import com.example.oid4vc.enrollment.core.transport.TransportProvider;
import com.example.oid4vc.enrollment.exception.SdkException;

/**
 * Builder class for creating EnrollEntitySDK instances.
 * Provides a fluent interface for configuring all SDK dependencies and options.
 */
public class EnrollEntityBuilder {
    
    private TransportProvider transportProvider;
    private CryptoProvider cryptoProvider;
    private EntityProvider entityProvider;
    private EnrollEntityConfig config;

    /**
     * Creates a new builder instance.
     *
     * @return a new EnrollEntityBuilder
     */
    public static EnrollEntityBuilder newBuilder() {
        return new EnrollEntityBuilder();
    }

    /**
     * Sets the transport provider.
     *
     * @param transportProvider the transport provider
     * @return this builder
     */
    public EnrollEntityBuilder withTransport(TransportProvider transportProvider) {
        this.transportProvider = transportProvider;
        return this;
    }

    /**
     * Sets the crypto provider.
     *
     * @param cryptoProvider the crypto provider
     * @return this builder
     */
    public EnrollEntityBuilder withCrypto(CryptoProvider cryptoProvider) {
        this.cryptoProvider = cryptoProvider;
        return this;
    }

    /**
     * Sets the signature provider.
     *
     * @param entityProvider the signature provider
     * @return this builder
     */
    public EnrollEntityBuilder withEntity(EntityProvider entityProvider) {
        this.entityProvider = entityProvider;
        return this;
    }

    /**
     * Sets the configuration.
     *
     * @param config the configuration
     * @return this builder
     */
    public EnrollEntityBuilder withConfig(EnrollEntityConfig config) {
        this.config = config;
        return this;
    }

    /**
     * Validates the builder configuration and creates the SDK instance.
     *
     * @return the configured EnrollEntitySDK instance
     * @throws SdkException if the configuration is invalid or required components are missing
     */
    public EnrollEntitySDK build() throws SdkException {
        validateConfiguration();

        if (transportProvider == null) {
          transportProvider = new DefaultTransportProvider(config.getTasApiBasePath());
        }

        return new EnrollEntitySDKImpl(
                transportProvider,
                cryptoProvider,
                entityProvider,
                config
        );
    }

    /**
     * Validates the builder configuration.
     *
     * @throws SdkException if configuration is invalid
     */
    private void validateConfiguration() throws SdkException {
        if (config == null) {
            throw new SdkException(
                    SdkException.ErrorCodes.INVALID_CONFIGURATION,
                    "Configuration is required"
            );
        }
        
        try {
            config.validate();
        } catch (IllegalArgumentException e) {
            throw new SdkException(
                    SdkException.ErrorCodes.INVALID_CONFIGURATION,
                    "Invalid configuration: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Creates a copy of this builder.
     *
     * @return a copy of this builder
     */
    public EnrollEntityBuilder copy() {
        EnrollEntityBuilder copy = new EnrollEntityBuilder();
        copy.transportProvider = this.transportProvider;
        copy.cryptoProvider = this.cryptoProvider;
        copy.entityProvider = this.entityProvider;
        copy.config = this.config;
        return copy;
    }
}