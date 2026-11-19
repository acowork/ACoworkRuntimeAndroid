package com.acowork.androidhost

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.media.projection.MediaProjectionManager
import android.os.Bundle

/** One-shot system dialog for MediaProjection. Used when Accessibility screenshots are unavailable (API 29). */
class ScreenCaptureConsentActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (AndroidUseHandler.hasProjection()) {
            setResult(RESULT_OK)
            finish()
            return
        }
        val mgr = getSystemService(MediaProjectionManager::class.java)
        startActivityForResult(mgr.createScreenCaptureIntent(), REQ)
    }

    @Deprecated("startActivityForResult is the public MediaProjection contract")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ) {
            AndroidUseHandler.onProjectionResult(applicationContext, resultCode, data)
        }
        finish()
    }

    companion object {
        private const val REQ = 77

        fun launch(context: Context) {
            val intent = Intent(context, ScreenCaptureConsentActivity::class.java)
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
        }
    }
}
