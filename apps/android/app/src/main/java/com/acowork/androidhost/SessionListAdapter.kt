package com.acowork.androidhost

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.acowork.androidhost.databinding.ItemSessionBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Session rows for one agent, newest activity first (the order
 * [AgentSessions] returns them in).
 *
 * Stateless apart from the submitted list: the row shows what the store knows
 * and nothing is clickable, because this APK hosts the Runtime and does not
 * carry a chat surface (ADR-AND-004 §1).
 */
class SessionListAdapter : RecyclerView.Adapter<SessionListAdapter.Holder>() {
    private val items = mutableListOf<AgentSession>()

    fun submit(rows: List<AgentSession>) {
        items.clear()
        items.addAll(rows)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val binding = ItemSessionBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return Holder(binding)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        holder.bind(items[position])
    }

    override fun getItemCount(): Int = items.size

    inner class Holder(private val binding: ItemSessionBinding) :
        RecyclerView.ViewHolder(binding.root) {
        fun bind(row: AgentSession) {
            val res = binding.root.resources
            binding.sessionTitle.text =
                row.displayTitle(res.getString(R.string.session_untitled))
            binding.sessionMeta.text = res.getString(
                R.string.session_meta,
                ageLabel(row.lastActiveAtMs),
                row.messageCount,
            )
        }

        /** The one place a [SessionAge] becomes a sentence. */
        private fun ageLabel(atMs: Long): String {
            val res = binding.root.resources
            return when (val age = SessionTimes.ageOf(System.currentTimeMillis(), atMs)) {
                SessionAge.JustNow -> res.getString(R.string.time_just_now)
                is SessionAge.Minutes -> res.getString(R.string.time_minutes_ago, age.count)
                is SessionAge.Hours -> res.getString(R.string.time_hours_ago, age.count)
                is SessionAge.Days -> res.getString(R.string.time_days_ago, age.count)
                is SessionAge.On -> formatDate(age.atMs)
            }
        }

        private fun formatDate(atMs: Long): String =
            SimpleDateFormat("MMM d", Locale.getDefault()).format(Date(atMs))
    }
}