package com.acowork.androidhost

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.acowork.androidhost.databinding.ItemAgentBinding

class AgentListAdapter(
    private val onClick: (AgentRow) -> Unit,
) : RecyclerView.Adapter<AgentListAdapter.Holder>() {
    private val items = mutableListOf<AgentRow>()

    fun submit(rows: List<AgentRow>) {
        val previous = items.toList()
        items.clear()
        items.addAll(rows)
        notifyDataSetChanged()
        previous.forEach { old ->
            val bitmap = old.avatar ?: return@forEach
            if (rows.none { it.avatar === bitmap }) bitmap.recycle()
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val binding = ItemAgentBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return Holder(binding)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        holder.bind(items[position])
    }

    override fun getItemCount(): Int = items.size

    inner class Holder(private val binding: ItemAgentBinding) : RecyclerView.ViewHolder(binding.root) {
        fun bind(row: AgentRow) {
            binding.agentName.text = row.name
            binding.agentPackage.text = row.packageId
            binding.agentStatus.setText(if (row.running) R.string.agent_running else R.string.agent_stopped)
            binding.agentStatus.setTextColor(if (row.running) 0xFF1B7A4A.toInt() else 0xFF8A8178.toInt())
            binding.agentAvatar.contentDescription = row.name
            val bitmap = row.avatar
            if (bitmap != null && !bitmap.isRecycled) {
                binding.agentAvatar.setImageBitmap(bitmap)
            } else if (row.avatarRes != 0) {
                binding.agentAvatar.setImageResource(row.avatarRes)
            } else {
                binding.agentAvatar.setImageDrawable(null)
            }
            binding.root.setOnClickListener { onClick(row) }
        }
    }
}
