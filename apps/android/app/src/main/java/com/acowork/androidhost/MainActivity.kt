package com.acowork.androidhost

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import com.acowork.androidhost.databinding.ActivityMainBinding
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var applyingEnroll = false

    private val cameraPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) launchScanner() else {
            Toast.makeText(this, R.string.camera_required, Toast.LENGTH_LONG).show()
        }
    }

    private val scanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val parsed = IntentIntegrator.parseActivityResult(result.resultCode, result.data)
        val text = parsed?.contents
        if (text.isNullOrBlank()) return@registerForActivityResult
        if (!applyEnrollText(text)) {
            Toast.makeText(this, R.string.scan_bad, Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        requestPostNotifications()
        requestSharedStorage()
        restoreFields()
        refreshNativeBanner()
        maybeApplyDeepLink(intent?.data?.toString())
        setupBottomNav()

        binding.tokenInput.doAfterTextChanged { editable ->
            if (applyingEnroll) return@doAfterTextChanged
            val raw = editable?.toString().orEmpty()
            if (looksLikeEnrollBlob(raw)) applyEnrollText(raw, toast = false)
        }

        binding.btnProbe.setOnClickListener { runProbe() }
        binding.btnPaste.setOnClickListener { pasteEnrollFromClipboard() }
        binding.btnScan.setOnClickListener { requestCameraAndScan() }
        binding.btnStart.setOnClickListener { startHost() }
        binding.btnStop.setOnClickListener {
            HostForegroundService.stop(this)
            binding.statusText.text = getString(R.string.status_stopped)
            refreshAgentsPanel()
        }
        binding.btnRefresh.setOnClickListener { refreshStatus() }
        binding.btnAgentsRefresh.setOnClickListener { refreshAgentsPanel() }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        maybeApplyDeepLink(intent.data?.toString())
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
        refreshAgentsPanel()
    }

    private fun setupBottomNav() {
        binding.bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_agents -> {
                    showPanel(agents = true)
                    refreshAgentsPanel()
                    true
                }
                R.id.nav_settings -> {
                    showPanel(agents = false)
                    refreshStatus()
                    true
                }
                else -> false
            }
        }
        binding.bottomNav.selectedItemId = R.id.nav_agents
        showPanel(agents = true)
    }

    private fun showPanel(agents: Boolean) {
        binding.panelAgents.visibility = if (agents) View.VISIBLE else View.GONE
        binding.panelSettings.visibility = if (agents) View.GONE else View.VISIBLE
    }

    private fun maybeApplyDeepLink(raw: String?) {
        applyEnrollText(raw ?: return, toast = false)
    }

    private fun looksLikeEnrollBlob(raw: String): Boolean {
        val t = raw.trim()
        return t.startsWith("acowork://", ignoreCase = true) ||
            t.startsWith("acowork-enroll://", ignoreCase = true) ||
            t.startsWith("{") ||
            t.contains("--token")
    }

    private fun applyEnrollText(raw: String, toast: Boolean = true): Boolean {
        val payload = EnrollQr.parse(raw) ?: return false
        applyingEnroll = true
        binding.gatewayInput.setText(payload.gateway)
        binding.tokenInput.setText(payload.token)
        applyingEnroll = false
        if (toast) Toast.makeText(this, R.string.scan_ok, Toast.LENGTH_SHORT).show()
        return true
    }

    private fun pasteEnrollFromClipboard() {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = cm.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString().orEmpty()
        if (text.isBlank()) {
            Toast.makeText(this, R.string.paste_empty, Toast.LENGTH_LONG).show()
            return
        }
        if (!applyEnrollText(text)) {
            Toast.makeText(this, R.string.scan_bad, Toast.LENGTH_LONG).show()
        }
    }

    private fun restoreFields() {
        val prefs = getSharedPreferences(HostForegroundService.PREFS, MODE_PRIVATE)
        val saved = prefs.getString(HostForegroundService.PREF_GATEWAY, "") ?: ""
        binding.gatewayInput.setText(
            when {
                saved.isNotBlank() && !saved.contains("127.0.0.1") -> saved
                else -> ""
            },
        )
        binding.tokenInput.setText(prefs.getString(HostForegroundService.PREF_TOKEN, "") ?: "")
        binding.nameInput.setText(prefs.getString(HostForegroundService.PREF_NAME, "") ?: "")
    }

    private fun refreshNativeBanner() {
        if (!Native.loaded) {
            binding.nativeBanner.text = getString(
                R.string.native_missing,
                Native.loadError ?: "unknown",
            )
            binding.btnStart.isEnabled = false
            binding.btnProbe.isEnabled = false
            binding.btnPaste.isEnabled = false
            binding.btnScan.isEnabled = false
        } else {
            val lan = NetUtil.lanIpv4() ?: "(no Wi‑Fi IP)"
            binding.nativeBanner.text = try {
                "${Native.version()}  dial-back=$lan:${HostForegroundService.NODE_PROXY_PORT}"
            } catch (t: Throwable) {
                t.message
            }
        }
    }

    private fun requestCameraAndScan() {
        when {
            ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED -> launchScanner()
            else -> cameraPermission.launch(Manifest.permission.CAMERA)
        }
    }

    private fun launchScanner() {
        val integrator = IntentIntegrator(this)
        integrator.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
        integrator.setPrompt(getString(R.string.scan_qr))
        integrator.setBeepEnabled(false)
        integrator.setOrientationLocked(false)
        scanLauncher.launch(integrator.createScanIntent())
    }

    private fun runProbe() {
        if (!Native.loaded) return
        lifecycleScope.launch {
            binding.statusText.text = getString(R.string.status_probing)
            val home = filesDir.resolve("acowork").absolutePath
            val json = withContext(Dispatchers.IO) {
                Native.probeSummary(home, packageName)
            }
            binding.statusText.text = json
        }
    }

    private fun startHost() {
        if (!Native.loaded) {
            Toast.makeText(this, R.string.native_required, Toast.LENGTH_LONG).show()
            return
        }
        val tokenRaw = binding.tokenInput.text?.toString().orEmpty()
        if (looksLikeEnrollBlob(tokenRaw)) applyEnrollText(tokenRaw, toast = false)

        val gateway = binding.gatewayInput.text?.toString()?.trim().orEmpty()
        if (gateway.isEmpty() || gateway.contains("127.0.0.1")) {
            Toast.makeText(this, R.string.gateway_required, Toast.LENGTH_SHORT).show()
            return
        }
        if (NetUtil.lanIpv4().isNullOrBlank()) {
            Toast.makeText(this, R.string.lan_ip_required, Toast.LENGTH_LONG).show()
            return
        }
        val token = binding.tokenInput.text?.toString()?.trim().orEmpty()
        val name = binding.nameInput.text?.toString()?.trim().orEmpty()
        HostForegroundService.start(this, gateway, token, name)
        binding.statusText.text = getString(R.string.status_starting)
        binding.root.postDelayed({
            refreshStatus()
            refreshAgentsPanel()
        }, 800)
    }

    private fun refreshStatus() {
        if (!Native.loaded) return
        lifecycleScope.launch {
            val json = withContext(Dispatchers.IO) { Native.nodeStatus() }
            binding.statusText.text = json
        }
    }

    private fun refreshAgentsPanel() {
        if (!Native.loaded) {
            binding.agentsSummary.text = getString(R.string.native_required)
            binding.agentsList.text = ""
            return
        }
        lifecycleScope.launch {
            val statusJson = withContext(Dispatchers.IO) { Native.nodeStatus() }
            val installed = withContext(Dispatchers.IO) {
                runCatching {
                    filesDir.resolve("acowork/installed.json").takeIf { it.exists() }?.readText()
                }.getOrNull()
            }
            renderAgents(statusJson, installed)
        }
    }

    private fun renderAgents(statusJson: String, installedJson: String?) {
        val status = runCatching { JSONObject(statusJson) }.getOrNull()
        val running = status?.optBoolean("running") == true
        val nodeName = status?.optString("node_name").orEmpty()
        val packages = status?.optInt("packages", -1) ?: -1
        if (!running) {
            binding.agentsSummary.text = getString(R.string.agents_host_down)
        } else {
            binding.agentsSummary.text = buildString {
                append(nodeName.ifBlank { "(node)" })
                append(" · running")
                if (packages >= 0) append(" · packages=").append(packages)
            }
        }

        val agents = installedJson
            ?.let { runCatching { JSONObject(it).optJSONObject("agents") }.getOrNull() }
        if (agents == null || agents.length() == 0) {
            binding.agentsList.text = getString(R.string.agents_empty)
            return
        }
        val lines = mutableListOf<String>()
        val keys = agents.keys()
        while (keys.hasNext()) {
            val id = keys.next()
            val row = agents.optJSONObject(id) ?: continue
            val name = row.optString("name").ifBlank { row.optString("agent_id") }
            val ver = row.optString("version")
            lines += "$name  $ver\n  instance=$id\n  package=${row.optString("agent_id")}"
        }
        lines.sort()
        binding.agentsList.text = lines.joinToString("\n\n")
    }

    private fun requestPostNotifications() {
        if (Build.VERSION.SDK_INT < 33) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            == PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        androidx.core.app.ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.POST_NOTIFICATIONS),
            1001,
        )
    }

    /** Shared-storage workspaces (/sdcard) are unreadable until this is granted. */
    private fun requestSharedStorage() {
        if (Build.VERSION.SDK_INT >= 33) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
            == PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        androidx.core.app.ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE),
            1002,
        )
    }
}
