package com.acowork.androidhost

import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import java.io.File

/**
 * One session row of an installed agent, as the agent's own session store
 * records it (`{home}/agents/{instanceId}/memory/private.sqlite`, table
 * `sessions`).
 *
 * Instance-local and read-only: the Runtime owns this store and writes it
 * while the agent runs, so the panel never mutates a row. The fields are the
 * ones the desktop session list shows — title, last activity, message count —
 * and nothing else, because the panel has no use for tokens, prompts or
 * message bodies (thin identity is the rule for this APK, ADR-AND-004 §2).
 */
data class AgentSession(
    val sessionId: String,
    /** `null` when the agent never named the session (desktop: "Untitled session"). */
    val title: String?,
    /**
     * Epoch ms of the last turn — the list's sort key, and the timestamp the
     * row shows. The desktop list sorts by this and *displays* `created_at`;
     * a phone row whose visible time disagreed with its position would read as
     * randomly ordered, so here the two are the same field.
     */
    val lastActiveAtMs: Long,
    val messageCount: Int,
) {
    /** The name to show, with the same fallback the desktop list uses. */
    fun displayTitle(fallback: String): String =
        title?.takeIf { it.isNotBlank() } ?: fallback
}

/** What the detail page can say about the session store. */
sealed interface SessionListResult {
    /**
     * The store answered. An empty list is a real answer (agent never chatted
     * on this phone), not an error, and must not be reported as one.
     */
    data class Loaded(val sessions: List<AgentSession>) : SessionListResult

    /** The store exists but could not be read — shown verbatim to the operator. */
    data class Failed(val reason: String) : SessionListResult
}

/**
 * Reads an agent's session list straight from the on-disk store.
 *
 * Why not the Runtime HTTP API (`GET /sessions`, what the desktop client
 * calls): the Node only keeps loopback ports for agents the Gateway has
 * started, and this panel has to answer "what ran on this phone" whether or
 * not that agent is up right now. The store is the same source of truth the
 * running Runtime answers from, so a read-only query cannot disagree with the
 * desktop — only lag it by the writing turn.
 *
 * Coupling is deliberate and confined to this file: the column list is the
 * `sessions` table contract owned by `acowork-memory` (schema.rs), the order is
 * `last_active_at DESC` — the store's own `list_recent` order, i.e. what the
 * desktop list shows — and the limit keeps a long-lived agent from
 * materialising thousands of rows into a phone screen.
 */
object AgentSessions {
    /** Hard cap on rows handed to the list; the page is a glance, not an archive. */
    const val MAX_ROWS = 200

    private const val STORE_REL = "memory/private.sqlite"

    private val SESSION_ID_CHARS = Regex("[A-Za-z0-9._-]{1,128}")

    /**
     * Load up to [limit] sessions for [instanceId], newest activity first.
     *
     * Never throws: a missing store means "this agent has no session rows on
     * this device" (the Runtime creates it on first boot), and an unreadable
     * one is reported as [SessionListResult.Failed] instead of an empty list —
     * "I could not look" and "there is nothing" are different answers.
     */
    fun load(home: File, instanceId: String, limit: Int = MAX_ROWS): SessionListResult {
        if (!SESSION_ID_CHARS.matches(instanceId)) {
            return SessionListResult.Failed("bad instance id")
        }
        val dbFile = File(File(File(home, "agents"), instanceId), STORE_REL)
        if (!dbFile.isFile) return SessionListResult.Loaded(emptyList())
        return try {
            SessionListResult.Loaded(query(dbFile, limit))
        } catch (e: Exception) {
            SessionListResult.Failed(e.message ?: e.toString())
        }
    }

    private fun query(dbFile: File, limit: Int): List<AgentSession> {
        val db = openReadOnly(dbFile)
        try {
            val rows = mutableListOf<AgentSession>()
            db.rawQuery(
                "SELECT session_id, title, last_active_at, message_count" +
                    " FROM sessions ORDER BY last_active_at DESC LIMIT ?",
                arrayOf(limit.coerceAtLeast(0).toString()),
            ).use { cursor ->
                while (cursor.moveToNext()) {
                    val sessionId = cursor.getString(0) ?: continue
                    rows += AgentSession(
                        sessionId = sessionId,
                        title = if (cursor.isNull(1)) null else cursor.getString(1),
                        lastActiveAtMs = cursor.getLong(2),
                        messageCount = if (cursor.isNull(3)) 0 else cursor.getInt(3),
                    )
                }
            }
            return rows
        } finally {
            db.close()
        }
    }

    /**
     * Open the store without any authority to write it.
     *
     * The Runtime keeps the file in WAL mode, and a read-only connection may
     * still need to touch the `-shm` sidecar; when that fails SQLite reports
     * it as a plain [SQLiteException]. Retrying once with write access (but
     * still without `CREATE`) recovers the case where the platform's read-only
     * open cannot attach the WAL index — we never issue a write either way.
     */
    private fun openReadOnly(dbFile: File): SQLiteDatabase =
        try {
            SQLiteDatabase.openDatabase(dbFile.path, null, SQLiteDatabase.OPEN_READONLY)
        } catch (e: SQLiteException) {
            SQLiteDatabase.openDatabase(dbFile.path, null, SQLiteDatabase.OPEN_READWRITE)
        }
}