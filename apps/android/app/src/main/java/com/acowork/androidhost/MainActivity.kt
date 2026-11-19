package com.acowork.androidhost

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import com.acowork.androidhost.databinding.ActivityMainBinding
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val agentList = AgentListAdapter { row -> openAgent(row) }
    private var applyingEnroll = false

    private val cameraPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) launchScanner() else {
            Toast.makeText(this, R.string.camera_required, Toast.LENGTH_LONG).show()
        }
    }

    private val devicePermission = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        val denied = result.filterValues { granted -> !granted }.keys
        val message = if (denied.isEmpty()) R.string.device_permissions_ok else R.string.device_permissions_denied
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
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
        binding.btnDevicePermissions.setOnClickListener { requestDevicePermissions(null) }
        binding.btnStart.setOnClickListener { startHost() }
        binding.btnStop.setOnClickListener {
            HostForegroundService.stop(this)
            binding.statusText.text = getString(R.string.status_stopped)
            refreshAgentsPanel()
        }
        binding.btnRefresh.setOnClickListener { refreshStatus() }
        binding.btnAgentsRefresh.setOnClickListener { refreshAgentsPanel() }
        binding.agentsList.layoutManager = LinearLayoutManager(this)
        binding.agentsList.adapter = agentList
        binding.agentsList.addItemDecoration(
            DividerItemDecoration(this, DividerItemDecoration.VERTICAL),
        )
        handleDeviceIntent(intent)
    }

    /** The row is the entry point. The agent screen for [row] is not built yet. */
    @Suppress("UNUSED_PARAMETER")
    private fun openAgent(row: AgentRow) {
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeviceIntent(intent)
        maybeApplyDeepLink(intent.data?.toString())
    }

    private fun handleDeviceIntent(intent: android.content.Intent?) {
        val permission = intent?.getStringExtra(DevicePermissions.EXTRA_PERMISSION)
        val usbDevice = intent?.getStringExtra(DevicePermissions.EXTRA_USB_DEVICE)
        if (permission == null && usbDevice == null) return
        selectNav(agents = false)
        if (permission != null) requestDevicePermissions(permission)
        if (usbDevice != null) requestUsbPermission(usbDevice)
    }

    private fun requestDevicePermissions(only: String?) {
        val requested = if (only != null) listOf(only) else DevicePermissions.declared()
        val missing = requested.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            Toast.makeText(this, R.string.device_permissions_none, Toast.LENGTH_SHORT).show()
            return
        }
        devicePermission.launch(missing.toTypedArray())
    }

    private fun requestUsbPermission(deviceName: String) {
        val usb = getSystemService(UsbManager::class.java)
        val device = usb.deviceList[deviceName] ?: return
        if (usb.hasPermission(device)) return
        usb.requestPermission(device, UsbHidHandler.permissionIntent(this))
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
        refreshAgentsPanel()
    }

    private fun setupBottomNav() {
        binding.navAgents.setOnClickListener { selectNav(agents = true) }
        binding.navSettings.setOnClickListener { selectNav(agents = false) }
        applyNavSelection(agents = true)
        showPanel(agents = true)
    }

    private fun selectNav(agents: Boolean) {
        applyNavSelection(agents)
        showPanel(agents)
        if (agents) refreshAgentsPanel() else refreshStatus()
    }

    private fun applyNavSelection(agents: Boolean) {
        binding.navAgents.isSelected = agents
        binding.navSettings.isSelected = !agents
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
            agentList.submit(emptyList())
            binding.agentsEmpty.visibility = View.VISIBLE
            return
        }
        lifecycleScope.launch {
            val statusJson = withContext(Dispatchers.IO) { Native.nodeStatus() }
            val home = filesDir.resolve("acowork")
            val installed = withContext(Dispatchers.IO) {
                runCatching { home.resolve("installed.json").takeIf { it.exists() }?.readText() }.getOrNull()
            }
            val rows = withContext(Dispatchers.IO) { AgentRows.load(this@MainActivity, home, installed) }
            renderAgents(statusJson, rows)
        }
    }

    private fun renderAgents(statusJson: String, rows: List<AgentRow>) {
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
        agentList.submit(rows)
        binding.agentsEmpty.visibility = if (rows.isEmpty()) View.VISIBLE else View.GONE
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
