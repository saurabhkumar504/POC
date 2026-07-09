package com.owasp.lab.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Secure replacement for the legacy deserialisation endpoint.
 *
 * REMEDIATION (OWASP A08:2021 - Software and Data Integrity Failures):
 *  - Native Java deserialisation (ObjectInputStream) is REMOVED entirely.
 *    It is replaced with a strict JSON parse using Jackson, which is
 *    not vulnerable to gadget-chain RCE because only declared POJO fields
 *    are populated.
 *  - fail-on-unknown-properties is enforced in the global Jackson
 *    configuration (see application.properties) so undeclared fields
 *    are rejected.
 *  - The endpoint accepts an arbitrary JSON object and echoes back the
 *    parsed type name so the lab's API shape is preserved.
 */
@RestController
@RequestMapping("/api/deserialize")
public class InsecureDeserializationController {

    private final ObjectMapper objectMapper;

    public InsecureDeserializationController(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> deserialize(@RequestBody String body) throws Exception {
        // SAFE: parse as untyped JSON (Map). Never call readObject().
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = objectMapper.readValue(body, Map.class);
        return ResponseEntity.ok(Map.of(
                "type", "Map<String,Object>",
                "size", parsed == null ? 0 : parsed.size()
        ));
    }
}
