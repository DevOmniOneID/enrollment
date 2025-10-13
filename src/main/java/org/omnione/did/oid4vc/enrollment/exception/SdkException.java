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

package org.omnione.did.oid4vc.enrollment.exception;

/**
 * Base exception class for DID SDK operations.
 * All SDK-specific exceptions should extend this class.
 */
public class SdkException extends RuntimeException {
    
    private final String errorCode;
    private final Object[] args;

    /**
     * Constructs a new SdkException with the specified error code and message.
     *
     * @param errorCode the error code
     * @param message the detail message
     */
    public SdkException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
        this.args = null;
    }

    /**
     * Constructs a new SdkException with the specified error code, message, and cause.
     *
     * @param errorCode the error code
     * @param message the detail message
     * @param cause the cause
     */
    public SdkException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.args = null;
    }

    /**
     * Constructs a new SdkException with the specified error code, message, and arguments.
     *
     * @param errorCode the error code
     * @param message the detail message
     * @param args the arguments for message formatting
     */
    public SdkException(String errorCode, String message, Object... args) {
        super(message);
        this.errorCode = errorCode;
        this.args = args;
    }

    /**
     * Returns the error code.
     *
     * @return the error code
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Returns the message arguments.
     *
     * @return the message arguments
     */
    public Object[] getArgs() {
        return args;
    }

    /**
     * Common error codes for SDK operations.
     */
    public static class ErrorCodes {
        public static final String INVALID_CONFIGURATION = "SDK_001";
        public static final String TRANSPORT_ERROR = "SDK_002";
        public static final String CRYPTO_ERROR = "SDK_003";
        public static final String SIGNATURE_ERROR = "SDK_004";
        public static final String WALLET_ERROR = "SDK_005";
        public static final String ENROLL_FAILED = "SDK_006";
    }
}