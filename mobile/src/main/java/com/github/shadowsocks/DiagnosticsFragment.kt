package com.github.shadowsocks

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.github.shadowsocks.bg.BaseService
import com.github.shadowsocks.bg.MorokssTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

class DiagnosticsFragment : ToolbarFragment() {
    private var report: String? = null
    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var runButton: Button
    private lateinit var saveButton: Button

    private val saveReport = registerForActivityResult(
            ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val data = report ?: return@registerForActivityResult
        if (uri == null) return@registerForActivityResult
        val message = try {
            requireContext().contentResolver.openOutputStream(uri)?.use {
                it.write(data.toByteArray(Charsets.UTF_8))
            } ?: error("No output stream")
            R.string.diagnostics_saved
        } catch (_: Exception) {
            R.string.diagnostics_save_failed
        }
        (activity as? MainActivity)?.snackbar(getString(message))?.show()
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, state: Bundle?): View =
            inflater.inflate(R.layout.layout_diagnostics, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        toolbar.title = getString(R.string.diagnostics_title)
        status = view.findViewById(R.id.diagnostics_status)
        progress = view.findViewById(R.id.diagnostics_progress)
        runButton = view.findViewById(R.id.diagnostics_run)
        saveButton = view.findViewById(R.id.diagnostics_save)
        runButton.setOnClickListener { startDiagnostic() }
        saveButton.setOnClickListener {
            saveReport.launch("morokss-diagnostic-${System.currentTimeMillis()}.json")
        }
    }

    private fun startDiagnostic() {
        val host = activity as? MainActivity ?: return
        val vpnActive = host.state != BaseService.State.Idle && host.state != BaseService.State.Stopped
        val profile = Core.currentProfile?.main
        val transport = try {
            profile?.let(MorokssTransport::from)
        } catch (_: IllegalArgumentException) {
            null
        }
        if (profile == null || transport == null) {
            status.setText(R.string.diagnostics_no_profile)
            return
        }
        report = null
        setRunning(true)
        viewLifecycleOwner.lifecycleScope.launch {
            val result = try {
                if (vpnActive) buildRuntimeReport(profile.id, true)
                else runNativeDiagnostic(transport, profile.id)
            } catch (_: Exception) {
                null
            }
            if (result == null) {
                status.setText(R.string.diagnostics_failed)
            } else {
                report = result
                status.setText(R.string.diagnostics_complete)
            }
            setRunning(false)
        }
    }

    private fun setRunning(running: Boolean) {
        progress.visibility = if (running) View.VISIBLE else View.GONE
        runButton.isEnabled = !running
        saveButton.isEnabled = !running && report != null
        if (running) status.setText(R.string.diagnostics_running)
    }

    private suspend fun runNativeDiagnostic(transport: MorokssTransport, profileId: Long): String? =
            withContext(Dispatchers.IO) {
        val context = requireContext().applicationContext
        val networkScope = networkScope(context)
        val command = transport.diagnosticCommand(
                context.applicationInfo.nativeLibraryDir, profileId, networkScope)
        val process = ProcessBuilder(command).apply {
            environment()["MOROKSS_SECRET"] = transport.secret
        }.start()
        val started = SystemClock.elapsedRealtime()
        try {
            coroutineScope {
                val stdout = async(Dispatchers.IO) { process.inputStream.bufferedReader().readText() }
                val stderr = async(Dispatchers.IO) { process.errorStream.bufferedReader().readText() }
                val exitCode = withTimeout(TimeUnit.MINUTES.toMillis(10)) {
                    while (true) {
                        try {
                            return@withTimeout process.exitValue()
                        } catch (_: IllegalThreadStateException) {
                            delay(100)
                        }
                    }
                    @Suppress("UNREACHABLE_CODE")
                    -1
                }
                val output = stdout.await()
                val stderrOutput = stderr.await()
                if (output.isBlank() || (exitCode != 0 && !output.trimStart().startsWith("{"))) {
                    return@coroutineScope null
                }
                val root = JSONObject(output)
                root.put("export_schema_version", 5)
                root.put("native_process", JSONObject().apply {
                    put("status", if (exitCode == 0) "complete" else "diagnostic_failed")
                    put("exit_code", exitCode)
                    put("duration_ms", SystemClock.elapsedRealtime() - started)
                    put("stderr_lines", stderrOutput.lineSequence().count { it.isNotBlank() })
                })
                addAndroidContext(root, context, profileId, false)
                root.toString(2) + "\n"
            }
        } finally {
            process.destroy()
        }
    }

    private suspend fun buildRuntimeReport(profileId: Long, vpnActive: Boolean): String =
            withContext(Dispatchers.IO) {
        val context = requireContext().applicationContext
        JSONObject().apply {
            put("schema_version", 5)
            put("client_version", BuildConfig.VERSION_NAME)
            put("generated_at", timestamp())
            put("self_test", JSONObject().apply {
                put("status", "skipped")
                put("reason", if (vpnActive) "vpn_active" else "not_requested")
            })
            addAndroidContext(this, context, profileId, vpnActive)
        }.toString(2) + "\n"
    }

    private fun addAndroidContext(root: JSONObject, context: Context, profileId: Long, vpnActive: Boolean) {
        root.put("android", JSONObject().apply {
            put("app_version", BuildConfig.VERSION_NAME)
            put("sdk_int", Build.VERSION.SDK_INT)
            put("network", networkScope(context))
            put("vpn_active", vpnActive)
            put("captured_at", timestamp())
            put("elapsed_realtime_ms", SystemClock.elapsedRealtime())
            put("connectivity", connectivitySnapshot(context))
        })
        root.put("runtime_trace", runtimeTraceSnapshot(profileId))
    }

    private fun runtimeTraceSnapshot(profileId: Long): JSONObject {
        val file = File(Core.deviceStorage.noBackupFilesDir, "morokss-$profileId-runtime.jsonl")
        val events = JSONArray()
        var malformed = 0
        if (file.isFile) file.bufferedReader().useLines { lines ->
            lines.take(6001).forEach { line ->
                if (line.isBlank()) return@forEach
                try {
                    events.put(JSONObject(line))
                } catch (_: Exception) {
                    malformed++
                }
            }
        }
        return JSONObject().apply {
            put("available", file.isFile)
            put("file_bytes", if (file.isFile) file.length() else 0)
            put("last_modified", if (file.isFile) utcTimestamp(file.lastModified()) else JSONObject.NULL)
            put("event_count", events.length())
            put("malformed_lines", malformed)
            put("summary", summarizeRuntimeEvents(events))
            put("events", events)
        }
    }

    private fun summarizeRuntimeEvents(events: JSONArray): JSONObject {
        val eventCounts = linkedMapOf<String, Int>()
        val errorCounts = linkedMapOf<String, Int>()
        val stageCounts = linkedMapOf<String, Int>()
        var uploadBytes = 0L
        var downloadBytes = 0L
        var observedUploadBytes = 0L
        var observedDownloadBytes = 0L
        var startedConnections = 0
        var completedConnections = 0
        var failedConnections = 0
        var retryAttempts = 0
        var maxSlotWait = 0L
        var maxGlobalActive = 0
        var maxDownloadActive = 0
        for (index in 0 until events.length()) {
            val event = events.optJSONObject(index) ?: continue
            val name = event.optString("event", "unknown")
            eventCounts[name] = (eventCounts[name] ?: 0) + 1
            event.optString("error_code").takeIf(String::isNotBlank)?.let {
                errorCounts[it] = (errorCounts[it] ?: 0) + 1
            }
            event.optString("stage").takeIf(String::isNotBlank)?.let {
                stageCounts[it] = (stageCounts[it] ?: 0) + 1
            }
            maxSlotWait = maxOf(maxSlotWait, event.optLong("slot_wait_ms"), event.optLong("max_slot_wait_ms"))
            maxGlobalActive = maxOf(maxGlobalActive, event.optInt("global_active"))
            maxDownloadActive = maxOf(maxDownloadActive, event.optInt("download_active"))
            if (name == "connection_start") startedConnections++
            val status = event.optString("status")
            if (name == "burst_attempt" && status != "failed" && status != "slot_failed") {
                if (event.optString("direction") == "upload") observedUploadBytes += event.optLong("bytes")
                if (event.optString("direction") == "download") observedDownloadBytes += event.optLong("bytes")
                if (event.optInt("attempt") > 1) retryAttempts++
            }
            if (name == "connection_finish") {
                completedConnections++
                if (event.optString("status") == "failed") failedConnections++
                uploadBytes += event.optLong("upload_bytes")
                downloadBytes += event.optLong("download_bytes")
            }
        }
        fun counts(values: Map<String, Int>) = JSONObject().apply {
            values.forEach { (key, value) -> put(key, value) }
        }
        return JSONObject().apply {
            put("started_connections", startedConnections)
            put("completed_connections", completedConnections)
            put("active_connections", maxOf(0, startedConnections - completedConnections))
            put("failed_connections", failedConnections)
            put("upload_bytes", uploadBytes)
            put("download_bytes", downloadBytes)
            put("observed_burst_upload_bytes", observedUploadBytes)
            put("observed_burst_download_bytes", observedDownloadBytes)
            put("retry_attempts", retryAttempts)
            put("max_slot_wait_ms", maxSlotWait)
            put("max_global_active", maxGlobalActive)
            put("max_download_active", maxDownloadActive)
            put("event_counts", counts(eventCounts))
            put("error_counts", counts(errorCounts))
            put("stage_counts", counts(stageCounts))
        }
    }

    private fun connectivitySnapshot(context: Context): JSONObject {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val network = underlyingNetwork(manager)
        val capabilities = network?.let(manager::getNetworkCapabilities)
        val links = network?.let(manager::getLinkProperties)
        val transports = JSONArray()
        listOf(
                NetworkCapabilities.TRANSPORT_CELLULAR to "cellular",
                NetworkCapabilities.TRANSPORT_WIFI to "wifi",
                NetworkCapabilities.TRANSPORT_ETHERNET to "ethernet",
                NetworkCapabilities.TRANSPORT_VPN to "vpn",
        ).forEach { (transport, name) ->
            if (capabilities?.hasTransport(transport) == true) transports.put(name)
        }
        return JSONObject().apply {
            put("underlying_network_present", network != null)
            put("vpn_network_present", manager.allNetworks.any {
                manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            })
            put("transports", transports)
            put("internet", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true)
            put("validated", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true)
            put("captive_portal", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true)
            put("not_restricted", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED) == true)
            put("not_metered", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == true)
            put("not_roaming", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING) == true)
            put("upstream_kbps", capabilities?.linkUpstreamBandwidthKbps ?: 0)
            put("downstream_kbps", capabilities?.linkDownstreamBandwidthKbps ?: 0)
            put("mtu", links?.mtu ?: 0)
            put("dns_server_count", links?.dnsServers?.size ?: 0)
            put("has_ipv4_default_route", links?.routes?.any {
                it.isDefaultRoute && it.destination.address.address.size == 4
            } == true)
            put("has_ipv6_default_route", links?.routes?.any {
                it.isDefaultRoute && it.destination.address.address.size == 16
            } == true)
            if (Build.VERSION.SDK_INT >= 28) {
                put("private_dns_active", links?.isPrivateDnsActive == true)
                put("not_congested", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED) == true)
                put("not_suspended", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED) == true)
            }
        }
    }

    private fun underlyingNetwork(manager: ConnectivityManager): Network? = manager.allNetworks.firstOrNull { network ->
        manager.getNetworkCapabilities(network)?.let {
            !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        } == true
    } ?: manager.activeNetwork

    private fun networkScope(context: Context): String {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val capabilities = manager.getNetworkCapabilities(underlyingNetwork(manager))
        return when {
            capabilities == null -> "offline"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
    }

    private fun timestamp(): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }.format(Date())

    private fun utcTimestamp(milliseconds: Long): String = SimpleDateFormat(
            "yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }.format(Date(milliseconds))
}
