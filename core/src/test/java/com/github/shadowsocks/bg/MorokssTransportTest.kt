package com.github.shadowsocks.bg

import com.github.shadowsocks.database.Profile
import com.github.shadowsocks.plugin.MorokssPlugin
import com.github.shadowsocks.plugin.PluginOptions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MorokssTransportTest {
    @Test
    fun parsesEndpointsAndDefaults() {
        val options = PluginOptions(MorokssPlugin.ID, null).apply {
            put("hostname", "vpn.example.com")
            put("secret", "0123456789abcdef0123456789abcdef")
            put("endpoint", "edge.example.com:443")
            put("endpoint_ipv4", "203.0.113.10")
            put("endpoint_ipv6", "2001:db8::10")
            put("endpoints", "edge2.example.com:8443,203.0.113.20:2053")
            put("cover_sni", "one.example.com, two.example.com,one.example.com")
            put("insecure", "true")
        }
        val transport = MorokssTransport.from(Profile(plugin = options.toString(false)))!!

        assertEquals("auto", transport.tlsProfile)
        assertEquals("auto", transport.wireTransport)
        assertEquals("auto", transport.coverSniMode)
        assertTrue(transport.insecure)
        assertEquals(listOf("one.example.com", "two.example.com"), transport.coverSnis)
        assertEquals(listOf(
                "edge.example.com:443",
                "203.0.113.10:443",
                "[2001:db8::10]:443",
                "edge2.example.com:8443",
                "203.0.113.20:2053",
        ), transport.endpoints)
    }

    @Test
    fun defaultsToSafeSniAndParsesManifest() {
        val options = PluginOptions(MorokssPlugin.ID, null).apply {
            put("hostname", "vpn.example.com")
            put("secret", "0123456789abcdef0123456789abcdef")
            put("endpoint", "edge.example.com:443")
            put("endpoint_manifest", "https://updates.example.com/endpoints.json")
            put("manifest_public_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        }
        val transport = MorokssTransport.from(Profile(plugin = options.toString(false)))!!

        assertEquals("off", transport.coverSniMode)
        assertEquals(emptyList<String>(), transport.coverSnis)
        assertEquals(listOf("https://updates.example.com/endpoints.json"), transport.manifestSources)
        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", transport.manifestPublicKey)
    }

    @Test
    fun ignoresRegularShadowsocksProfile() {
        assertEquals(null, MorokssTransport.from(Profile(plugin = null)))
    }

    @Test
    fun rejectsShortSecret() {
        val options = PluginOptions(MorokssPlugin.ID, null).apply {
            put("hostname", "vpn.example.com")
            put("secret", "short")
            put("endpoint", "edge.example.com:443")
        }
        try {
            MorokssTransport.from(Profile(plugin = options.toString(false)))
            throw AssertionError("short secret was accepted")
        } catch (error: IllegalArgumentException) {
            assertTrue(error.message.orEmpty().contains("32"))
        }
    }
}
