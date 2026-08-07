package com.github.shadowsocks.bg

import com.github.shadowsocks.Core
import com.github.shadowsocks.core.BuildConfig
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
        val coverSnis: List<String>,
        val coverSniMode: String,
        val manifestSources: List<String>,
        val manifestPublicKey: String,
        val insecure: Boolean,
        val burstUpload: Boolean,
        val burstChunk: Int,
        val burstParallel: Int,
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
            val extraEndpoints = options["endpoints"].orEmpty().split(',')
                    .map(String::trim).filter(String::isNotEmpty)
            val endpoints = (listOf(primary, options["endpoint_ipv4"], options["endpoint_ipv6"]) +
                    extraEndpoints)
                    .mapNotNull { it?.trim()?.takeIf(String::isNotEmpty) }
                    .map { addPort(it, port) }
                    .distinct()
            val coverSnis = options["cover_sni"].orEmpty().split(',')
                    .map(String::trim).filter(String::isNotEmpty).distinct()
            val coverSniMode = options["cover_sni_mode"].orEmpty()
                    .ifBlank { if (coverSnis.isEmpty()) "off" else "auto" }
            require(coverSniMode == "auto" || coverSniMode == "off") {
                "MorokSS: cover_sni_mode must be auto or off"
            }
            val manifestSources = options["endpoint_manifest"].orEmpty()
                    .split(',').map(String::trim).filter(String::isNotEmpty).distinct()
            val manifestPublicKey = options["manifest_public_key"].orEmpty().trim()
            require(manifestSources.isEmpty() == manifestPublicKey.isEmpty()) {
                "MorokSS: endpoint_manifest and manifest_public_key must be set together"
            }
            // Existing MorokSS profiles predate Burst and therefore have no option at all.
            // Enable it by default so an app update also fixes those saved profiles; an
            // explicit false remains available for troubleshooting and rollback.
            val burstUpload = options["burst_upload"].orEmpty().ifBlank { "true" }
                    .equals("true", ignoreCase = true)
            val burstChunk = options["burst_chunk"].orEmpty().ifBlank { "8192" }.toIntOrNull()
                    ?: throw IllegalArgumentException("MorokSS: burst_chunk must be an integer")
            require(burstChunk in 1024..8192) {
                "MorokSS: burst_chunk must be between 1024 and 8192 bytes"
            }
            val burstParallel = options["burst_parallel"].orEmpty().ifBlank { "4" }.toIntOrNull()
                    ?: throw IllegalArgumentException("MorokSS: burst_parallel must be an integer")
            require(burstParallel in 1..8) {
                "MorokSS: burst_parallel must be between 1 and 8"
            }
            return MorokssTransport(
                    hostname,
                    secret,
                    endpoints,
                    options["profile"].orEmpty().ifBlank { "auto" },
                    options["transport"].orEmpty().ifBlank { "auto" },
                    coverSnis,
                    coverSniMode,
                    manifestSources,
                    manifestPublicKey,
                    options["insecure"].equals("true", ignoreCase = true) && BuildConfig.DEBUG,
                    burstUpload,
                    burstChunk,
                    burstParallel,
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

    fun command(nativeLibraryDir: String, isVpnService: Boolean, profileId: Long, networkScope: String): List<String> = buildList {
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
        add("--cover-sni-mode")
        add(coverSniMode)
        add("--cover-sni-cache")
        add(File(state, "morokss-$profileId-cover-sni.cache").absolutePath)
        add("--network-scope")
        add(networkScope)
        coverSnis.forEach {
            add("--cover-sni")
            add(it)
        }
        if (manifestSources.isNotEmpty()) {
            val publicKey = File(state, "morokss-$profileId-manifest-public.key")
            publicKey.writeText(manifestPublicKey + "\n", Charsets.UTF_8)
            publicKey.setReadable(false, false)
            publicKey.setWritable(false, false)
            publicKey.setReadable(true, true)
            publicKey.setWritable(true, true)
            manifestSources.forEach {
                add("--endpoint-manifest")
                add(it)
            }
            add("--manifest-public-key")
            add(publicKey.absolutePath)
            add("--manifest-cache")
            add(File(state, "morokss-$profileId-manifest.cache").absolutePath)
        }
        if (insecure) add("--insecure")
        if (burstUpload) {
            add("--burst-upload")
            add("--burst-chunk")
            add(burstChunk.toString())
            add("--burst-parallel")
            add(burstParallel.toString())
        }
        endpoints.forEach {
            add("--endpoint")
            add("$it,$hostname")
        }
        if (isVpnService) {
            add("--protect-path")
            add(File(state, "protect_path").absolutePath)
        }
    }

    fun diagnosticCommand(nativeLibraryDir: String, profileId: Long, networkScope: String): List<String> =
            command(nativeLibraryDir, false, profileId, networkScope) + listOf(
                    "--diagnose",
                    "--diagnose-network",
                    "tcp",
            )
}
