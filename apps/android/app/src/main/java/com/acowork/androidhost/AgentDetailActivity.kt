package com.acowork.androidhost

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import com.acowork.androidhost.databinding.ActivityAgentDetailBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

/**
 * Second-level page of the Agents screen: the session history of one agent
 * instance, newest activity first.
 *
 * Scope is read-only by design — this APK is the Node host, not the chat
 * client, so a session row is something to read, not to open (ADR-AND-004 §1).
 * The page therefore renders exactly three states: rows, "no sessions yet", and
 * "the store could not be read".
 *
 * The instance id is the only input: the header re-derives name, package and
 * running state from the same sources the Agents list uses
 * ([AgentRows.identity] + `Native.nodeStatus`), so the two screens cannot drift.
 */
class AgentDetailActivity : AppCompatActivity() {
    private lateinit var binding: ActivityAgentDetailBinding
    private val sessionList = SessionListAdapter()
    private lateinit var instanceId: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAgentDetailBinding.inflate(layoutInflater)
        setContentView(binding.root)

        instanceId = intent.getStringExtra(EXTRA_INSTANCE_ID).orEmpty()
        binding.btnBack.setOnClickListener { onBackPressedDispatcher.onBackPressed() }
        binding.btnSessionsRefresh.setOnClickListener { load() }
        binding.sessionList.layoutManager = LinearLayoutManager(this)
        binding.sessionList.adapter = sessionList
        binding.sessionList.addItemDecoration(
            DividerItemDecoration(this, DividerItemDecoration.VERTICAL),
        )
        if (instanceId.isBlank()) {
            renderError("missing instance id")
            return
        }
        renderIdentity(null, statusJson = "")
    }

    override fun onResume() {
        super.onResume()
        load()
    }

    /** Header + list both come from disk, so one pass refreshes the whole page. */
    private fun load() {
        if (instanceId.isBlank()) return
        val home = filesDir.resolve("acowork")
        lifecycleScope.launch {
            val statusJson = withContext(Dispatchers.IO) {
                if (Native.loaded) Native.nodeStatus() else ""
            }
            val installed = withContext(Dispatchers.IO) {
                runCatching { home.resolve("installed.json").takeIf { it.exists() }?.readText() }
                    .getOrNull()
            }
            val row = withContext(Dispatchers.IO) {
                AgentRows.identity(home, installed, instanceId)
            }
            val result = withContext(Dispatchers.IO) { AgentSessions.load(home, instanceId) }
            renderIdentity(row, statusJson)
            renderSessions(result)
        }
    }

    private fun renderIdentity(row: AgentIdentity?, statusJson: String) {
        binding.detailName.text = row?.name ?: instanceId
        binding.detailMeta.text = when {
            row == null -> getString(R.string.agent_detail_meta_missing, instanceId)
            else -> getString(
                R.string.agent_detail_meta,
                row.packageId.ifBlank { instanceId },
                getString(
                    if (isAgentRunning(row, statusJson)) R.string.agent_running
                    else R.string.agent_stopped,
                ),
            )
        }
    }

    /**
     * Both halves have to agree: [AgentRows] proves an engine process carries
     * this instance id, and the node's own `running` flag rules out a leftover
     * process from a host that has since been stopped.
     */
    private fun isAgentRunning(row: AgentIdentity, statusJson: String): Boolean {
        if (!row.running) return false
        val status = runCatching { JSONObject(statusJson) }.getOrNull()
        return status?.optBoolean("running") == true
    }

    private fun renderSessions(result: SessionListResult) {
        when (result) {
            is SessionListResult.Loaded -> {
                binding.sessionError.visibility = View.GONE
                sessionList.submit(result.sessions)
                binding.sessionEmpty.visibility =
                    if (result.sessions.isEmpty()) View.VISIBLE else View.GONE
                binding.sessionsSummary.text = if (result.sessions.isEmpty()) {
                    getString(R.string.agent_detail_sessions_empty)
                } else {
                    // Counted in code, not via <plurals>: this UI ships English
                    // strings only, and on a zh device the platform picks the
                    // "other" form for 1 ("1 sessions").
                    getString(
                        if (result.sessions.size == 1) R.string.session_count_one
                        else R.string.session_count_other,
                        result.sessions.size,
                    )
                }
            }

            is SessionListResult.Failed -> renderError(result.reason)
        }
    }

    private fun renderError(reason: String) {
        sessionList.submit(emptyList())
        binding.sessionEmpty.visibility = View.GONE
        binding.sessionError.text = getString(R.string.session_error, reason)
        binding.sessionError.visibility = View.VISIBLE
        binding.sessionsSummary.text = ""
    }

    companion object {
        private const val EXTRA_INSTANCE_ID = "com.acowork.androidhost.extra.INSTANCE_ID"

        fun intent(context: Context, instanceId: String): Intent =
            Intent(context, AgentDetailActivity::class.java)
                .putExtra(EXTRA_INSTANCE_ID, instanceId)
    }
}