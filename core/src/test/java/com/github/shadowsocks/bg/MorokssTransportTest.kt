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
        }
        val transport = MorokssTransport.from(Profile(plugin = options.toString(false)))!!

        assertEquals("auto", transport.tlsProfile)
        assertEquals("auto", transport.wireTransport)
        assertEquals(listOf(
                "edge.example.com:443",
                "203.0.113.10:443",
                "[2001:db8::10]:443",
        ), transport.endpoints)
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
