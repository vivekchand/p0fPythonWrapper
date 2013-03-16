import p0fmod
p0fmod.set_iface("eth0")
p0fmod.set_api_sock("/tmp/sock")
#p0fmod.en_daemon_mode()
p0fmod.start_p0f()
