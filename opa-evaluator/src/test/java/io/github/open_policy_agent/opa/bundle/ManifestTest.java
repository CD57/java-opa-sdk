package io.github.open_policy_agent.opa.bundle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ManifestTest {

  @Test
  void exposesKnownFieldsAndRetainsExtensions() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("revision", "abc123");
    properties.put("roots", List.of("authz", "roles"));
    properties.put("rego_version", 1);
    properties.put("file_rego_versions", Map.of("/legacy.rego", 0));
    properties.put("metadata", Map.of("team", "security"));
    properties.put("wasm", List.of(Map.of("entrypoint", "authz/allow")));
    properties.put("default_decision", "authz/allow");
    properties.put("vendor_extension", Map.of("enabled", true));

    Manifest manifest = Manifest.fromMap(properties);

    assertEquals("abc123", manifest.getRevision());
    assertTrue(manifest.hasRoots());
    assertEquals(List.of("authz", "roles"), manifest.getRoots());
    assertEquals(1, manifest.getRegoVersion());
    assertEquals(Map.of("/legacy.rego", 0), manifest.getFileRegoVersions());
    assertEquals(Map.of("team", "security"), manifest.getMetadata());
    assertEquals("authz/allow", manifest.getWasm().get(0).getEntrypoint());
    assertEquals("", manifest.getWasm().get(0).getModule());
    assertEquals("authz/allow", manifest.getDefaultDecision());
    assertEquals(
        Map.of("vendor_extension", Map.of("enabled", true)),
        manifest.getAdditionalProperties());
    assertEquals(properties, manifest.asMap());
  }

  @Test
  void distinguishesAbsentRootsFromExplicitEmptyRoots() {
    Manifest absent = Manifest.fromMap(Map.of("revision", "one"));
    Manifest empty = Manifest.fromMap(Map.of("revision", "two", "roots", List.of()));

    assertFalse(absent.hasRoots());
    assertEquals(List.of(""), absent.getRoots());
    assertTrue(empty.hasRoots());
    assertTrue(empty.getRoots().isEmpty());
  }

  @Test
  @SuppressWarnings("unchecked")
  void makesDefensiveImmutableCopy() {
    List<Object> labels = new ArrayList<>(List.of("stable"));
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("labels", labels);
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("metadata", metadata);

    Manifest manifest = Manifest.fromMap(properties);
    labels.add("mutated");
    metadata.put("new", true);
    properties.put("revision", "late");

    assertEquals(Map.of("labels", List.of("stable")), manifest.getMetadata());
    assertEquals("", manifest.getRevision());
    assertThrows(
        UnsupportedOperationException.class,
        () -> manifest.getMetadata().put("another", true));
    assertThrows(
        UnsupportedOperationException.class,
        () -> ((List<Object>) manifest.getMetadata().get("labels")).add("another"));
    assertThrows(
        UnsupportedOperationException.class,
        () -> manifest.asMap().put("another", true));
  }

  @Test
  void rejectsInvalidKnownFieldTypes() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("revision", 123)));
    IllegalArgumentException badRoot =
        assertThrows(
            IllegalArgumentException.class,
            () -> Manifest.fromMap(Map.of("roots", List.of("valid", 123))));
    assertEquals("Manifest field 'roots' must be array of strings, got Integer", badRoot.getMessage());
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("rego_version", 1.5)));
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("rego_version", 1.0)));
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("file_rego_versions", Map.of("/policy.rego", "one"))));
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("metadata", List.of())));
  }

  @Test
  void appliesOpaDefaultsToNullFieldsWithoutChangingRawRepresentation() {
    Map<String, Object> properties = new LinkedHashMap<>();
    for (String field : List.of("revision", "roots", "rego_version", "file_rego_versions", "metadata", "wasm")) {
      properties.put(field, null);
    }
    Manifest manifest = Manifest.fromMap(properties);

    assertEquals("", manifest.getRevision());
    assertFalse(manifest.hasRoots());
    assertEquals(List.of(""), manifest.getRoots());
    assertNull(manifest.getRegoVersion());
    assertEquals(Map.of(), manifest.getFileRegoVersions());
    assertEquals(Map.of(), manifest.getMetadata());
    assertEquals(List.of(), manifest.getWasm());
    assertEquals(properties, manifest.asMap());
  }

  @Test
  void decodesNullCollectionElementsLikeGo() {
    Map<String, Object> versions = new LinkedHashMap<>();
    versions.put("/legacy.rego", null);
    Manifest manifest = Manifest.fromMap(Map.of(
        "roots", Arrays.asList("authz", null),
        "file_rego_versions", versions,
        "wasm", Arrays.asList((Object) null)));

    assertEquals(List.of("authz", ""), manifest.getRoots());
    assertEquals(Map.of("/legacy.rego", 0), manifest.getFileRegoVersions());
    assertEquals(Map.of(), manifest.getWasm().get(0).asMap());
    assertEquals("", manifest.getWasm().get(0).getEntrypoint());
  }

  @Test
  void wasmResolversAreTypedImmutableAndPreserveRawFields() {
    Map<String, Object> annotation = new LinkedHashMap<>(Map.of("title", "Allow"));
    Map<String, Object> resolver = new LinkedHashMap<>();
    resolver.put("entrypoint", "authz/allow");
    resolver.put("module", "/policy.wasm");
    resolver.put("annotations", Arrays.asList(annotation, null));
    resolver.put("extension", true);
    Manifest manifest = Manifest.fromMap(Map.of("wasm", List.of(resolver)));
    Manifest.WasmResolver wasm = manifest.getWasm().get(0);

    assertEquals("authz/allow", wasm.getEntrypoint());
    assertEquals("/policy.wasm", wasm.getModule());
    assertEquals(resolver, wasm.asMap());
    assertEquals(wasm, Manifest.fromMap(manifest.asMap()).getWasm().get(0));
    assertEquals(wasm.hashCode(), Manifest.fromMap(manifest.asMap()).getWasm().get(0).hashCode());
    annotation.put("title", "changed");
    resolver.put("module", "changed");
    assertEquals("Allow", wasm.getAnnotations().get(0).get("title"));
    assertEquals(Map.of(), wasm.getAnnotations().get(1));
    assertEquals("/policy.wasm", wasm.getModule());
    assertThrows(UnsupportedOperationException.class, () -> wasm.asMap().put("module", "changed"));
    assertThrows(UnsupportedOperationException.class, () -> wasm.getAnnotations().get(0).put("title", "changed"));
    assertThrows(UnsupportedOperationException.class, () -> wasm.getAnnotations().clear());
    assertThrows(UnsupportedOperationException.class, () -> manifest.getWasm().clear());
  }

  @Test
  void checksIntegerBoundsWithoutLossyConversions() {
    assertEquals(1, Manifest.fromMap(Map.of("rego_version", BigInteger.ONE)).getRegoVersion());
    assertThrows(IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("rego_version", BigInteger.ONE.shiftLeft(64))));
    assertThrows(IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("rego_version", Long.MAX_VALUE)));
  }

  @Test
  void rejectsWrongContainerTypesAndNonStringKeys() {
    assertEquals(
        "Manifest field 'roots' must be array of strings, got String",
        assertThrows(
                IllegalArgumentException.class,
                () -> Manifest.fromMap(Map.of("roots", "authz")))
            .getMessage());
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("wasm", Map.of("entrypoint", "authz/allow"))));
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("wasm", List.of("authz/allow"))));
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("rego_version", "1")));
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("metadata", Map.of(1, "not a string key"))));
  }

  @Test
  void acceptsEveryJsonCompatibleScalarType() {
    Map<String, Object> scalars = new LinkedHashMap<>();
    scalars.put("byte", (byte) 1);
    scalars.put("short", (short) 2);
    scalars.put("long", 3L);
    scalars.put("bigInteger", BigInteger.TEN);
    scalars.put("bigDecimal", new BigDecimal("1.5"));
    scalars.put("float", 1.5f);
    scalars.put("double", 2.5d);
    scalars.put("boolean", true);
    scalars.put("nothing", null);
    Manifest manifest = Manifest.fromMap(Map.of("metadata", scalars, "rego_version", (short) 1));

    assertEquals(scalars, manifest.getMetadata());
    assertEquals(1, manifest.getRegoVersion());
    assertThrows(
        IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("metadata", Map.of("number", Float.NaN))));
  }

  @Test
  void equalityUsesRawRepresentation() {
    Manifest defaulted = Manifest.fromMap(Map.of());
    Manifest explicit = Manifest.fromMap(Map.of("roots", List.of("")));
    Manifest same = Manifest.fromMap(new LinkedHashMap<>(Map.of("roots", List.of(""))));

    assertEquals(defaulted.getRoots(), explicit.getRoots());
    assertNotEquals(defaulted, explicit);
    assertEquals(explicit, same);
    assertEquals(explicit.hashCode(), same.hashCode());
    assertEquals(explicit, explicit);
    assertNotEquals(explicit, Map.of("roots", List.of("")));
    assertEquals("{roots=[]}", explicit.toString());
  }

  @Test
  void rejectsMutableAndNonJsonNumbers() {
    assertThrows(IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("metadata", Map.of("number", new AtomicInteger(1)))));
    assertThrows(IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("metadata", Map.of("number", Double.NaN))));
    assertThrows(IllegalArgumentException.class,
        () -> Manifest.fromMap(Map.of("metadata", Map.of("number", Double.POSITIVE_INFINITY))));
  }
}
