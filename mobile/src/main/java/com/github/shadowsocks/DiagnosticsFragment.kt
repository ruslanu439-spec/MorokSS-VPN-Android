package com.github.shadowsocks

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
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
import org.json.JSONObject
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
        if (host.state != BaseService.State.Idle && host.state != BaseService.State.Stopped) {
            status.setText(R.string.diagnostics_vpn_active)
            return
        }
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
                runNativeDiagnostic(transport, profile.id)
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
        try {
            coroutineScope {
                val stdout = async(Dispatchers.IO) { process.inputStream.bufferedReader().readText() }
                val stderr = async(Dispatchers.IO) { process.errorStream.bufferedReader().readText() }
                val exitCode = withTimeout(TimeUnit.MINUTES.toMillis(5)) {
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
                stderr.await()
                if (output.isBlank() || (exitCode != 0 && !output.trimStart().startsWith("{"))) {
                    return@coroutineScope null
                }
                val root = JSONObject(output)
                root.put("android", JSONObject().apply {
                    put("app_version", BuildConfig.VERSION_NAME)
                    put("sdk_int", Build.VERSION.SDK_INT)
                    put("network", networkScope)
                    put("captured_at", timestamp())
                })
                root.toString(2) + "\n"
            }
        } finally {
            process.destroy()
        }
    }

    private fun networkScope(context: Context): String {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val capabilities = manager.getNetworkCapabilities(manager.activeNetwork)
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
}
