package com.acowork.androidhost

/**
 * JNI bridge to `libacowork_android_ffi.so` (crate `acowork-android-ffi`).
 *
 * All methods return JSON strings unless noted. Load failures surface as
 * [UnsatisfiedLinkError] — the Activity shows a build hint instead of crashing.
 */
object Native {
    @Volatile
    var loaded: Boolean = false
        private set

    @Volatile
    var loadError: String? = null
        private set

    init {
        try {
            System.loadLibrary("acowork_android_ffi")
            loaded = true
        } catch (t: Throwable) {
            loadError = t.message ?: t.toString()
            loaded = false
        }
    }

    external fun version(): String
    external fun probeSummary(home: String, packageName: String): String
    external fun settingsCatalog(): String
    external fun loadHostConfig(home: String): String
    external fun saveHostConfig(home: String, json: String): String
    external fun startNode(
        home: String,
        gatewayHttp: String,
        enrollmentToken: String,
        nodeName: String,
        advertiseHost: String,
        advertisePort: String,
        enginePath: String,
    ): String
    external fun stopNode(): String
    external fun nodeStatus(): String
}
