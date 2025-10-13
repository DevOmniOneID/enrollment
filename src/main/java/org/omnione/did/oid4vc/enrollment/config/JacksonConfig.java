package org.omnione.did.oid4vc.enrollment.config;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import lombok.extern.slf4j.Slf4j;
import org.omnione.did.data.model.enums.profile.EccCurveType;

import java.io.IOException;
import java.lang.reflect.Method;

@Slf4j
public class JacksonConfig {

  public static ObjectMapper createObjectMapper() {
    ObjectMapper mapper = new ObjectMapper();

    // 커스텀 모듈 등록
    SimpleModule enumModule = new SimpleModule();

    // EccCurveType 커스텀 직렬화/역직렬화
    enumModule.addSerializer(EccCurveType.class, new EccCurveTypeSerializer());
    enumModule.addDeserializer(EccCurveType.class, new EccCurveTypeDeserializer());

    // SymmetricCipherType 처리
    try {
      Class<?> symmetricCipherTypeClass = Class.forName("org.omnione.did.data.model.enums.profile.SymmetricCipherType");
      if (symmetricCipherTypeClass.isEnum()) {
        enumModule.addSerializer((Class) symmetricCipherTypeClass, new RawValueEnumSerializer());
        enumModule.addDeserializer((Class) symmetricCipherTypeClass, new RawValueEnumDeserializer(symmetricCipherTypeClass));
      }
    } catch (ClassNotFoundException e) {
      // System.err.println("SymmetricCipherType class not found: " + e.getMessage());  // 삭제
      log.warn("SymmetricCipherType class not found: {}", e.getMessage());  // 추가
    }

    mapper.registerModule(enumModule);

    // 기본 설정
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    return mapper;
  }

  // Inner class들도 로깅이 필요한 경우
  @Slf4j  // Inner class에도 적용 가능
  public static class EccCurveTypeSerializer extends JsonSerializer<EccCurveType> {
    @Override
    public void serialize(EccCurveType value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
      try {
        Method getRawValue = value.getClass().getMethod("getRawValue");
        Object rawValue = getRawValue.invoke(value);
        gen.writeString(rawValue.toString());
      } catch (Exception e) {
        log.debug("Failed to get rawValue for EccCurveType, using name() instead: {}", e.getMessage());  // 추가
        gen.writeString(value.name());
      }
    }
  }

  @Slf4j
  public static class EccCurveTypeDeserializer extends JsonDeserializer<EccCurveType> {
    @Override
    public EccCurveType deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      String value = p.getValueAsString();
      if (value == null) return null;

      // name()으로 시도
      for (EccCurveType curve : EccCurveType.values()) {
        if (curve.name().equalsIgnoreCase(value)) {
          return curve;
        }
      }

      // rawValue로 시도
      for (EccCurveType curve : EccCurveType.values()) {
        try {
          Method getRawValue = curve.getClass().getMethod("getRawValue");
          Object rawValue = getRawValue.invoke(curve);
          if (rawValue.toString().equalsIgnoreCase(value)) {
            return curve;
          }
        } catch (Exception e) {
          log.trace("Failed to get rawValue for curve {}: {}", curve, e.getMessage());  // 추가 (선택사항)
        }
      }

      log.error("Unknown EccCurveType value: {}", value);  // 추가
      throw new IllegalArgumentException("Unknown EccCurveType: " + value);
    }
  }

  @Slf4j
  public static class RawValueEnumSerializer extends JsonSerializer<Enum> {
    @Override
    public void serialize(Enum value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
      try {
        Method getRawValue = value.getClass().getMethod("getRawValue");
        Object rawValue = getRawValue.invoke(value);
        gen.writeString(rawValue.toString());
      } catch (Exception e) {
        log.debug("Failed to get rawValue for {}, using name() instead: {}",
            value.getClass().getSimpleName(), e.getMessage());  // 추가
        gen.writeString(value.name());
      }
    }
  }

  @Slf4j
  public static class RawValueEnumDeserializer extends JsonDeserializer<Enum> {
    private final Class<? extends Enum> enumClass;

    public RawValueEnumDeserializer(Class<?> enumClass) {
      this.enumClass = (Class<? extends Enum>) enumClass;
    }

    @Override
    public Enum deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      String value = p.getValueAsString();
      if (value == null) return null;

      Enum[] enumConstants = enumClass.getEnumConstants();

      // name()으로 시도
      for (Enum enumConstant : enumConstants) {
        if (enumConstant.name().equalsIgnoreCase(value)) {
          return enumConstant;
        }
      }

      // rawValue로 시도
      for (Enum enumConstant : enumConstants) {
        try {
          Method getRawValue = enumConstant.getClass().getMethod("getRawValue");
          Object rawValue = getRawValue.invoke(enumConstant);
          if (rawValue.toString().equalsIgnoreCase(value)) {
            return enumConstant;
          }
        } catch (Exception e) {
          log.trace("Failed to get rawValue for {}: {}", enumConstant, e.getMessage());  // 추가 (선택사항)
        }
      }

      log.error("Unknown {} value: {}", enumClass.getSimpleName(), value);  // 추가
      throw new IllegalArgumentException("Unknown " + enumClass.getSimpleName() + ": " + value);
    }
  }
}