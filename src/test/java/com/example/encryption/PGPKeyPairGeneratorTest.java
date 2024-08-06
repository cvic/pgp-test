package com.example.encryption;

import static org.junit.Assert.*;

import org.junit.Test;

public class PGPKeyPairGeneratorTest {
    
    @Test
    public void testKeyGeneration() {
        try {
            PGPKeyPairGenerator pgpKeyPairGenerator = new PGPKeyPairGenerator();
            assertNotNull(pgpKeyPairGenerator.generatePGPKeyPair());
            assertNotNull(pgpKeyPairGenerator.generateAESKey());
        } catch (Exception e) {
            fail("Key generation failed: " + e.getMessage());
        }
    }
}
