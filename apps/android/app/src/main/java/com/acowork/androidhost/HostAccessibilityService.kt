package com.acowork.androidhost

import android.accessibilityservice.AccessibilityService
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent

/**
 * Cross-app screen observe/act for [AndroidUseHandler]. The user must enable
 * this in system Accessibility settings; the app cannot turn it on itself.
 */
class HostAccessibilityService : AccessibilityService() {
    val mainHandler = Handler(Looper.getMainLooper())

    override fun onServiceConnected() {
        instance = this
    }

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        if (instance === this) instance = null
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        super.onDestroy()
    }

    override fun onInterrupt() {}

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}

    companion object {
        @Volatile
        var instance: HostAccessibilityService? = null
            private set

        fun connected(): Boolean = instance != null
    }
}
