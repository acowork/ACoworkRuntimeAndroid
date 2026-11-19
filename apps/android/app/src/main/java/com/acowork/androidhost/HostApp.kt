package com.acowork.androidhost

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

class HostApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                HostForegroundService.CHANNEL_ID,
                getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.notification_channel_desc)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
            manager.createNotificationChannel(
                NotificationChannel(
                    "acowork_device",
                    getString(R.string.notification_channel_device),
                    NotificationManager.IMPORTANCE_HIGH,
                ).apply {
                    description = getString(R.string.notification_channel_device)
                },
            )
        }
    }
}
