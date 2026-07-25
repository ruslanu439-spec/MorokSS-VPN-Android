package com.github.shadowsocks.bg

import com.github.shadowsocks.Core
import com.github.shadowsocks.database.Profile
import com.github.shadowsocks.plugin.MorokssPlugin
import com.github.shadowsocks.plugin.PluginConfiguration
import java.io.File
import java.net.ServerSocket

data class MorokssTransport(
        val hostname: String,
        val secret: String,
        val endpoints: List<String>,
        val tlsProfile: String,
        val wireTransport: String,
) {
    companion object {
        fun from(profile: Profile): MorokssTransport? {
            val configuration = PluginConfiguration(profile.plugin ?: "")
            if (configuration.selected != MorokssPlugin.ID) return null
            val options = configuration.getOptions()
            val hostname = options["hostname"].orEmpty().trim()
            val secret = options["secret"].orEmpty()
            require(hostname.isNotEmpty()) { "MorokSS: hostname is required" }
            require(secret.toByteArray(Charsets.UTF_8).size >= 32) {
                "MorokSS: secret must contain at least 32 UTF-8 bytes"
            }

            val primary = options["endpoint"].orEmpty().ifBlank { profile.formattedAddress }
            val port = endpointPort(primary)
            val endpoints = listOf(primary, options["endpoint_ipv4"], options["endpoint_ipv6"])
                    .mapNotNull { it?.trim()?.takeIf(String::isNotEmpty) }
                    .map { addPort(it, port) }
                    .distinct()
            return MorokssTransport(
                    hostname,
                    secret,
                    endpoints,
                    options["profile"].orEmpty().ifBlank { "auto" },
                    options["transport"].orEmpty().ifBlank { "auto" },
            )
        }

        private fun endpointPort(endpoint: String): Int {
            if (endpoint.startsWith("[")) {
                return endpoint.substringAfter("]:", "443").toIntOrNull() ?: 443
            }
            return if (endpoint.count { it == ':' } == 1) {
                endpoint.substringAfterLast(':').toIntOrNull() ?: 443
            } else 443
        }

        private fun addPort(endpoint: String, port: Int): String {
            if (endpoint.startsWith("[") && endpoint.contains("]:")) return endpoint
            if (endpoint.startsWith("[") && endpoint.endsWith("]")) return "$endpoint:$port"
            return when (endpoint.count { it == ':' }) {
                0 -> "$endpoint:$port"
                1 -> if (endpoint.substringAfterLast(':').toIntOrNull() != null) endpoint else "$endpoint:$port"
                else -> "[$endpoint]:$port"
            }
        }
    }

    val localPort: Int by lazy { ServerSocket(0).use { it.localPort } }

    fun command(nativeLibraryDir: String, isVpnService: Boolean, profileId: Long): List<String> = buildList {
        val state = Core.deviceStorage.noBackupFilesDir
        add(File(nativeLibraryDir, Executable.MOROKSS).absolutePath)
        add("--listen")
        add("127.0.0.1:$localPort")
        add("--udp-listen")
        add("127.0.0.1:$localPort")
        add("--profile")
        add(tlsProfile)
        add("--transport")
        add(wireTransport)
        add("--profile-cache")
        add(File(state, "morokss-$profileId-tls.cache").absolutePath)
        add("--transport-cache")
        add(File(state, "morokss-$profileId-transport.cache").absolutePath)
        add("--endpoint-cache")
        add(File(state, "morokss-$profileId-endpoint.cache").absolutePath)
        endpoints.forEach {
            add("--endpoint")
            add("$it,$hostname")
        }
        if (isVpnService) {
            add("--protect-path")
            add(File(state, "protect_path").absolutePath)
        }
    }
}
