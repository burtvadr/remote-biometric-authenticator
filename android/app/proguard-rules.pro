# Keep the protocol data classes: their names appear in canonical encodings and in
# audit records, and obfuscating them would make protocol traces unreadable
# without changing any wire format.
-keep class io.github.burtvadr.rba.protocol.** { *; }

# Compose and AndroidX supply their own consumer rules.
-dontwarn kotlinx.coroutines.**
