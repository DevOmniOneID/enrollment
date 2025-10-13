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

package org.omnione.did.oid4vc.enrollment.core.enroll;

import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;
import org.omnione.did.data.model.enums.profile.EccCurveType;
import org.omnione.did.data.model.enums.profile.SymmetricCipherType;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Configuration class for enrollment entity SDK.
 * Contains all configurable parameters for the enrollment process.
 */
@Data
@Builder(toBuilder = true)
@Jacksonized
public class EnrollEntityConfig {

  /**
   * Base URL of the TAS (Trust Anchor Service).
   * Example: "https://tas.example.com"
   */
  private String tasBaseUrl;

  /**
   * API version to use for TAS communication.
   * Defaults to "v1".
   */
  @Builder.Default
  private String tasApiVersion = "v1";

  /**
   * Full TAS API base path.
   * If not provided, will be constructed from tasBaseUrl and tasApiVersion.
   */
  private String tasApiBasePath;

  /**
   * Connection timeout in milliseconds.
   * Defaults to 30 seconds.
   */
  @Builder.Default
  private int connectionTimeoutMs = 30000;

  /**
   * Read timeout in milliseconds.
   * Defaults to 30 seconds.
   */
  @Builder.Default
  private int readTimeoutMs = 30000;

  /**
   * Overall enrollment timeout in milliseconds.
   * Defaults to 5 minutes.
   */
  @Builder.Default
  private long enrollmentTimeoutMs = 300000L;

  /**
   * Default elliptic curve type for cryptographic operations.
   * Defaults to SECP256R1.
   */
  @Builder.Default
  private EccCurveType defaultCurveType = EccCurveType.SECP256R1;

  /**
   * List of supported symmetric cipher types for ECDH.
   * Defaults to all available cipher types.
   */
  @Builder.Default
  private List<SymmetricCipherType> supportedCiphers = Arrays.asList(SymmetricCipherType.values());

  /**
   * Length of client nonce in bytes.
   * Defaults to 16 bytes.
   */
  @Builder.Default
  private int nonceLength = 16;

  /**
   * Maximum number of retry attempts for API calls.
   * Defaults to 3.
   */
  @Builder.Default
  private int maxRetryAttempts = 3;

  /**
   * Delay between retry attempts in milliseconds.
   * Defaults to 1 second.
   */
  @Builder.Default
  private long retryDelayMs = 1000L;

  /**
   * Custom headers to be included in all API requests.
   * Defaults to empty map.
   */
  @Builder.Default
  private Map<String, String> customHeaders = Map.of();

  /**
   * Additional configuration properties for extensions.
   * Defaults to empty map.
   */
  @Builder.Default
  private Map<String, Object> additionalProperties = Map.of();

  /**
   * Creates a default configuration with standard settings.
   *
   * @param tasBaseUrl the TAS base URL
   * @return a default EnrollEntityConfig instance
   */
  public static EnrollEntityConfig defaultConfig(String tasBaseUrl) {
    return EnrollEntityConfig.builder()
        .tasBaseUrl(tasBaseUrl)
        .build();
  }

  /**
   * Creates a configuration for development/testing purposes.
   *
   * @param tasBaseUrl the TAS base URL
   * @return a development EnrollEntityConfig instance
   */
  public static EnrollEntityConfig developmentConfig(String tasBaseUrl) {
    return EnrollEntityConfig.builder()
        .tasBaseUrl(tasBaseUrl)
        .connectionTimeoutMs(60000)
        .readTimeoutMs(60000)
        .enrollmentTimeoutMs(600000L) // 10 minutes
        .maxRetryAttempts(1) // No retries in development
        .build();
  }

  /**
   * Creates a configuration for production use.
   *
   * @param tasBaseUrl the TAS base URL
   * @return a production EnrollEntityConfig instance
   */
  public static EnrollEntityConfig productionConfig(String tasBaseUrl) {
    return EnrollEntityConfig.builder()
        .tasBaseUrl(tasBaseUrl)
        .connectionTimeoutMs(15000)
        .readTimeoutMs(15000)
        .maxRetryAttempts(3)
        .retryDelayMs(2000L)
        .build();
  }

  /**
   * Gets the full TAS API base path.
   * If tasApiBasePath is set, returns it directly.
   * Otherwise, constructs it from tasBaseUrl and tasApiVersion.
   *
   * @return the full TAS API base path
   */
  public String getTasApiBasePath() {
    if (tasApiBasePath != null && !tasApiBasePath.isEmpty()) {
      return tasApiBasePath;
    }

    String baseUrl = tasBaseUrl;
    if (baseUrl.endsWith("/")) {
      baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
    }

    return baseUrl + "/tas/api/" + tasApiVersion;
  }

  /**
   * Validates the configuration and throws exception if invalid.
   *
   * @throws IllegalArgumentException if configuration is invalid
   */
  public void validate() {
    if (tasBaseUrl == null || tasBaseUrl.trim().isEmpty()) {
      throw new IllegalArgumentException("TAS base URL is required");
    }

    if (connectionTimeoutMs <= 0) {
      throw new IllegalArgumentException("Connection timeout must be positive");
    }

    if (readTimeoutMs <= 0) {
      throw new IllegalArgumentException("Read timeout must be positive");
    }

    if (enrollmentTimeoutMs <= 0) {
      throw new IllegalArgumentException("Enrollment timeout must be positive");
    }

    if (nonceLength <= 0 || nonceLength > 64) {
      throw new IllegalArgumentException("Nonce length must be between 1 and 64 bytes");
    }

    if (maxRetryAttempts < 0 || maxRetryAttempts > 10) {
      throw new IllegalArgumentException("Max retry attempts must be between 0 and 10");
    }

    if (retryDelayMs < 0) {
      throw new IllegalArgumentException("Retry delay must be non-negative");
    }

    if (supportedCiphers == null || supportedCiphers.isEmpty()) {
      throw new IllegalArgumentException("At least one supported cipher is required");
    }
  }
}