package com.github.shadowsocks.plugin

/** Built into the app; unlike SIP003 plugins this transport carries both TCP and UDP. */
object MorokssPlugin : Plugin() {
    const val ID = "morokss"

    override val id: String get() = ID
    override val label: CharSequence get() = "MorokSS (TCP + UDP)"
    override val defaultConfig: String get() = "profile=auto;transport=auto"
    override val packageName: String get() = "com.morokss.vpn"
}
