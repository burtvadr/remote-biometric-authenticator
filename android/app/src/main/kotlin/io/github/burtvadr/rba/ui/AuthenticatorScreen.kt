@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package io.github.burtvadr.rba.ui

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.AutoAwesome
import androidx.compose.material.icons.outlined.BatteryFull
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Computer
import androidx.compose.material.icons.outlined.Fullscreen
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Layers
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.burtvadr.rba.appearance.AppIconStyle
import io.github.burtvadr.rba.appearance.ThemeMode
import io.github.burtvadr.rba.ui.theme.FingerprintBadge

/**
 * What the app can currently do while it is not on screen.
 *
 * Kept as plain data so the activity reads the platform flags and the screen
 * only explains them.
 */
data class BackgroundStatus(
    val notificationsAllowed: Boolean,
    val canDrawOverlays: Boolean,
    val ignoringBatteryOptimizations: Boolean,
    val fullScreenIntentAllowed: Boolean,
    val notificationOnly: Boolean = false,
) {
    val ready: Boolean
        get() = notificationsAllowed && (notificationOnly || canDrawOverlays)
}

private enum class Tab { OVERVIEW, SETTINGS }

@Composable
fun AuthenticatorScreen(
    state: ScreenState,
    deviceId: String,
    deviceName: String,
    capabilities: SecurityPresentation?,
    hosts: List<HostPresentation>,
    connectedHostId: String?,
    discoveredKeyIds: Set<String>,
    background: BackgroundStatus,
    themeMode: ThemeMode,
    iconStyle: AppIconStyle,
    dynamicColor: Boolean,
    onThemeModeChange: (ThemeMode) -> Unit,
    onIconStyleChange: (AppIconStyle) -> Unit,
    onDynamicColorChange: (Boolean) -> Unit,
    onConfirmPairing: (String?) -> Boolean,
    onRejectPairing: () -> Unit,
    onForgetHost: (String) -> Boolean,
    onFixNotifications: () -> Unit,
    onFixOverlay: () -> Unit,
    onFixBattery: () -> Unit,
    onFixFullScreen: () -> Unit,
    versionName: String,
    isDebug: Boolean,
    modifier: Modifier = Modifier,
) {
    var selectedTab by rememberSaveable { mutableStateOf(Tab.OVERVIEW.name) }
    val operatorState = state !is ScreenState.Idle

    Scaffold(
        modifier = modifier,
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            if (!operatorState) {
                AppBottomBar(
                    selected = Tab.entries.firstOrNull { it.name == selectedTab } ?: Tab.OVERVIEW,
                    onSelect = { selectedTab = it.name },
                )
            }
        },
    ) { padding ->
        if (operatorState) {
            OperatorContent(
                state = state,
                iconStyle = iconStyle,
                onConfirmPairing = onConfirmPairing,
                onRejectPairing = onRejectPairing,
                modifier = Modifier.padding(padding),
            )
        } else {
            when (Tab.entries.firstOrNull { it.name == selectedTab } ?: Tab.OVERVIEW) {
                Tab.OVERVIEW -> OverviewScreen(
                    deviceId = deviceId,
                    deviceName = deviceName,
                    capabilities = capabilities,
                    hosts = hosts,
                    connectedHostId = connectedHostId,
                    discoveredKeyIds = discoveredKeyIds,
                    background = background,
                    iconStyle = iconStyle,
                    onForgetHost = onForgetHost,
                    onFixNotifications = onFixNotifications,
                    onFixOverlay = onFixOverlay,
                    onFixBattery = onFixBattery,
                    onFixFullScreen = onFixFullScreen,
                    modifier = Modifier.padding(padding),
                )
                Tab.SETTINGS -> SettingsScreen(
                    themeMode = themeMode,
                    iconStyle = iconStyle,
                    dynamicColor = dynamicColor,
                    onThemeModeChange = onThemeModeChange,
                    onIconStyleChange = onIconStyleChange,
                    onDynamicColorChange = onDynamicColorChange,
                    versionName = versionName,
                    isDebug = isDebug,
                    modifier = Modifier.padding(padding),
                )
            }
        }
    }
}

@Composable
private fun AppBottomBar(selected: Tab, onSelect: (Tab) -> Unit) {
    Column {
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
            NavigationBarItem(
                selected = selected == Tab.OVERVIEW,
                onClick = { onSelect(Tab.OVERVIEW) },
                icon = {
                    Icon(
                        if (selected == Tab.OVERVIEW) Icons.Filled.Home else Icons.Outlined.Home,
                        contentDescription = null,
                    )
                },
                label = { Text("Overview") },
                colors = NavigationBarItemDefaults.colors(
                    indicatorColor = MaterialTheme.colorScheme.primary,
                    selectedIconColor = MaterialTheme.colorScheme.onPrimary,
                    selectedTextColor = MaterialTheme.colorScheme.onSurface,
                    unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
            )
            NavigationBarItem(
                selected = selected == Tab.SETTINGS,
                onClick = { onSelect(Tab.SETTINGS) },
                icon = {
                    Icon(
                        if (selected == Tab.SETTINGS) Icons.Filled.Settings else Icons.Outlined.Settings,
                        contentDescription = null,
                    )
                },
                label = { Text("Settings") },
                colors = NavigationBarItemDefaults.colors(
                    indicatorColor = MaterialTheme.colorScheme.primary,
                    selectedIconColor = MaterialTheme.colorScheme.onPrimary,
                    selectedTextColor = MaterialTheme.colorScheme.onSurface,
                    unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

@Composable
private fun OverviewScreen(
    deviceId: String,
    deviceName: String,
    capabilities: SecurityPresentation?,
    hosts: List<HostPresentation>,
    connectedHostId: String?,
    discoveredKeyIds: Set<String>,
    background: BackgroundStatus,
    iconStyle: AppIconStyle,
    onForgetHost: (String) -> Boolean,
    onFixNotifications: () -> Unit,
    onFixOverlay: () -> Unit,
    onFixBattery: () -> Unit,
    onFixFullScreen: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showPairHelp by rememberSaveable { mutableStateOf(false) }
    var selectedHost by remember { mutableStateOf<HostPresentation?>(null) }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        item {
            PageHeader(
                title = "Overview",
                subtitle = "Remote biometric authenticator for your computer.",
            )
        }
        item {
            HeroCard(
                deviceName = deviceName,
                hosts = hosts,
                background = background,
                iconStyle = iconStyle,
                onPairClick = { showPairHelp = true },
            )
        }
        item { SectionHeader("Paired hosts") }
        item {
            PairedHostsCard(
                hosts = hosts,
                connectedHostId = connectedHostId,
                discoveredKeyIds = discoveredKeyIds,
                onHostClick = { selectedHost = it },
                onHowPairing = { showPairHelp = true },
            )
        }
        item { SectionHeader("Background operation") }
        item {
            BackgroundCard(
                status = background,
                onFixNotifications = onFixNotifications,
                onFixOverlay = onFixOverlay,
                onFixBattery = onFixBattery,
                onFixFullScreen = onFixFullScreen,
            )
        }
        item { SectionHeader("Security") }
        item {
            SecurityCard(
                deviceId = deviceId,
                capabilities = capabilities,
            )
        }
        item { Spacer(Modifier.height(4.dp)) }
    }

    if (showPairHelp) {
        PairingHelpDialog(onDismiss = { showPairHelp = false })
    }
    selectedHost?.let { host ->
        HostDetailsDialog(
            host = host,
            authenticatorDeviceId = deviceId,
            reachability = reachabilityOf(host, connectedHostId, discoveredKeyIds),
            onUnpair = onForgetHost,
            onDismiss = { selectedHost = null },
        )
    }
}

@Composable
private fun cardContainer(): Color =
    MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)

@Composable
private fun PageHeader(title: String, subtitle: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            title,
            style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            subtitle,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary,
        fontWeight = FontWeight.SemiBold,
    )
}

@Composable
private fun HeroCard(
    deviceName: String,
    hosts: List<HostPresentation>,
    background: BackgroundStatus,
    iconStyle: AppIconStyle,
    onPairClick: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(
            containerColor = cardContainer(),
        ),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                FingerprintBadge(style = iconStyle, size = 76.dp)
                Spacer(Modifier.width(16.dp))
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        deviceName,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        "Remote authenticator",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(2.dp))
                    StatusPill(hostCount = hosts.size, background = background)
                }
            }
            Button(
                onClick = onPairClick,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape = CircleShape,
                colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
            ) {
                Icon(Icons.Outlined.Link, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Pair a host")
            }
        }
    }
}

@Composable
private fun StatusPill(hostCount: Int, background: BackgroundStatus) {
    val (label, container, content) = when {
        hostCount == 0 -> Triple(
            "Not paired",
            MaterialTheme.colorScheme.errorContainer,
            MaterialTheme.colorScheme.onErrorContainer,
        )
        background.ready -> Triple(
            "Ready",
            MaterialTheme.colorScheme.primary,
            MaterialTheme.colorScheme.onPrimary,
        )
        else -> Triple(
            "Setup needed",
            MaterialTheme.colorScheme.tertiaryContainer,
            MaterialTheme.colorScheme.onTertiaryContainer,
        )
    }
    Surface(
        shape = CircleShape,
        color = container,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .size(7.dp)
                    .background(content, CircleShape),
            )
            Spacer(Modifier.width(6.dp))
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = content,
                fontWeight = FontWeight.SemiBold,
            )
        }
    }
}

/**
 * Per-host reachability, derived from the idle link and the last mDNS discovery.
 * "Not seen" is deliberately not "offline": a host that is up but not advertising
 * (guest network, multicast filtered) is also not seen.
 */
private enum class HostReachability { CONNECTED, AVAILABLE, NOT_SEEN }

private fun reachabilityOf(
    host: HostPresentation,
    connectedHostId: String?,
    discoveredKeyIds: Set<String>,
): HostReachability = when {
    connectedHostId != null && host.hostId == connectedHostId -> HostReachability.CONNECTED
    host.keyId in discoveredKeyIds -> HostReachability.AVAILABLE
    else -> HostReachability.NOT_SEEN
}

@Composable
private fun HostStatusBadge(reachability: HostReachability) {
    val (label, color) = when (reachability) {
        HostReachability.CONNECTED -> "Connected" to MaterialTheme.colorScheme.primary
        HostReachability.AVAILABLE -> "Available" to MaterialTheme.colorScheme.secondary
        HostReachability.NOT_SEEN -> "Not seen" to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(7.dp).background(color, CircleShape))
        Spacer(Modifier.width(5.dp))
        Text(label, style = MaterialTheme.typography.labelSmall, color = color)
    }
}

@Composable
private fun PairedHostsCard(
    hosts: List<HostPresentation>,
    connectedHostId: String?,
    discoveredKeyIds: Set<String>,
    onHostClick: (HostPresentation) -> Unit,
    onHowPairing: () -> Unit,
) {
    if (hosts.isEmpty()) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(
                containerColor = cardContainer(),
            ),
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    Icons.Outlined.Computer,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
                Text("No paired hosts", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Start pairing on the host with `rba pair`, then enter the " +
                        "code on this device.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TextButton(onClick = onHowPairing) { Text("How pairing works") }
            }
        }
    } else {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(
                containerColor = cardContainer(),
            ),
        ) {
            Column {
                hosts.forEachIndexed { index, host ->
                    ListItem(
                        headlineContent = { Text(host.hostName) },
                        supportingContent = {
                            Text(
                                "ID ${host.hostId.take(16)}…",
                                fontFamily = FontFamily.Monospace,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        },
                        leadingContent = {
                            Icon(
                                Icons.Outlined.Computer,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                            )
                        },
                        trailingContent = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                HostStatusBadge(
                                    reachabilityOf(host, connectedHostId, discoveredKeyIds)
                                )
                                Spacer(Modifier.width(4.dp))
                                Icon(Icons.Outlined.ChevronRight, contentDescription = null)
                            }
                        },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier.clickable { onHostClick(host) },
                    )
                    if (index != hosts.lastIndex) {
                        HorizontalDivider(
                            modifier = Modifier.padding(horizontal = 16.dp),
                            color = MaterialTheme.colorScheme.outlineVariant,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun BackgroundCard(
    status: BackgroundStatus,
    onFixNotifications: () -> Unit,
    onFixOverlay: () -> Unit,
    onFixBattery: () -> Unit,
    onFixFullScreen: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = cardContainer(),
        ),
    ) {
        Column {
            Text(
                if (status.notificationOnly) "One protected link; reconnects automatically. Open notifications to review requests." else "One idle link; it does not poll while the connection is healthy.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp),
            )
            PermissionRow(
                label = "Notifications",
                description = "Shows an authentication request",
                icon = Icons.Outlined.Notifications,
                ok = status.notificationsAllowed,
                onFix = onFixNotifications,
            )
            PermissionRow(
                label = "Open over other apps",
                description = if(status.notificationOnly) "Not required: requests open from notifications" else "Lets the prompt appear over the current app",
                icon = Icons.Outlined.Layers,
                ok = status.notificationOnly || status.canDrawOverlays,
                onFix = onFixOverlay,
            )
            PermissionRow(
                label = "Full-screen fallback",
                description = if(status.notificationOnly) "Not required: requests use protected review" else "Used when overlay access is unavailable",
                icon = Icons.Outlined.Fullscreen,
                ok = status.notificationOnly || status.fullScreenIntentAllowed,
                onFix = onFixFullScreen,
            )
            PermissionRow(
                label = "Battery optimisation",
                description = "Keeps the idle link alive",
                icon = Icons.Outlined.BatteryFull,
                ok = status.ignoringBatteryOptimizations,
                onFix = onFixBattery,
            )
        }
    }
}

@Composable
private fun PermissionRow(
    label: String,
    description: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    ok: Boolean,
    onFix: () -> Unit,
) {
    ListItem(
        headlineContent = { Text(label) },
        supportingContent = {
            Text(description, style = MaterialTheme.typography.bodySmall)
        },
        leadingContent = {
            Icon(
                if (ok) Icons.Outlined.CheckCircle else icon,
                contentDescription = null,
                tint = if (ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            )
        },
        trailingContent = if (ok) {
            null
        } else {
            { TextButton(onClick = onFix) { Text("Allow") } }
        },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
    )
}

@Composable
private fun SecurityCard(
    deviceId: String,
    capabilities: SecurityPresentation?,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = cardContainer(),
        ),
    ) {
        Column {
            InfoRow(
                "Strong biometric",
                if (capabilities?.strongBiometricEnrolled == true) "Enrolled" else "Not enrolled",
                valueColor = if (capabilities?.strongBiometricEnrolled == true) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.error
                },
            )
            HorizontalDivider(
                modifier = Modifier.padding(horizontal = 16.dp),
                color = MaterialTheme.colorScheme.outlineVariant,
            )
            InfoRow("Key storage", keyLocationLabel(capabilities))
            HorizontalDivider(
                modifier = Modifier.padding(horizontal = 16.dp),
                color = MaterialTheme.colorScheme.outlineVariant,
            )
            InfoRow("Device ID", "${deviceId.take(16)}…", monospace = true)
            HorizontalDivider(
                modifier = Modifier.padding(horizontal = 16.dp),
                color = MaterialTheme.colorScheme.outlineVariant,
            )
            InfoRow("Transport", "Wi-Fi · pinned TLS")
            Text(
                "The private key never leaves the Keystore; signing is gated by a " +
                    "strong biometric prompt.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
        }
    }
}

@Composable
private fun InfoRow(
    label: String,
    value: String,
    monospace: Boolean = false,
    valueColor: Color = MaterialTheme.colorScheme.onSurface,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = valueColor,
            fontFamily = if (monospace) FontFamily.Monospace else null,
            textAlign = TextAlign.End,
        )
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

@Composable
private fun SettingsScreen(
    themeMode: ThemeMode,
    iconStyle: AppIconStyle,
    dynamicColor: Boolean,
    onThemeModeChange: (ThemeMode) -> Unit,
    onIconStyleChange: (AppIconStyle) -> Unit,
    onDynamicColorChange: (Boolean) -> Unit,
    versionName: String,
    isDebug: Boolean,
    modifier: Modifier = Modifier,
) {
    var showThemeDialog by rememberSaveable { mutableStateOf(false) }
    var showIconDialog by rememberSaveable { mutableStateOf(false) }
    val supportsDynamicColor = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        item {
            PageHeader(
                title = "Settings",
                subtitle = "Appearance and build information.",
            )
        }
        item { SectionHeader("Appearance") }
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(
                    containerColor = cardContainer(),
                ),
            ) {
                Column {
                    SettingRow(
                        title = "Theme",
                        subtitle = themeMode.label,
                        leading = { Icon(Icons.Outlined.Palette, contentDescription = null) },
                        trailing = { Icon(Icons.Outlined.ChevronRight, contentDescription = null) },
                        onClick = { showThemeDialog = true },
                    )
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        color = MaterialTheme.colorScheme.outlineVariant,
                    )
                    SwitchRow(
                        title = "Dynamic color",
                        subtitle = if (supportsDynamicColor) {
                            "Use Material You wallpaper colors"
                        } else {
                            "Requires Android 12"
                        },
                        leading = { Icon(Icons.Outlined.AutoAwesome, contentDescription = null) },
                        checked = dynamicColor,
                        enabled = supportsDynamicColor,
                        onCheckedChange = onDynamicColorChange,
                    )
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        color = MaterialTheme.colorScheme.outlineVariant,
                    )
                    SettingRow(
                        title = "Icon style",
                        subtitle = iconStyle.label,
                        leading = { FingerprintBadge(style = iconStyle, size = 48.dp) },
                        trailing = { Icon(Icons.Outlined.ChevronRight, contentDescription = null) },
                        onClick = { showIconDialog = true },
                    )
                }
            }
        }
        item { SectionHeader("About") }
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(
                    containerColor = cardContainer(),
                ),
            ) {
                Column {
                    InfoRow("Version", versionName, monospace = true)
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        color = MaterialTheme.colorScheme.outlineVariant,
                    )
                    InfoRow("Protocol", "RBA v1", monospace = true)
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        color = MaterialTheme.colorScheme.outlineVariant,
                    )
                    InfoRow("Build", if (isDebug) "Debug" else "Release")
                }
            }
        }
        item { Spacer(Modifier.height(4.dp)) }
    }

    if (showThemeDialog) {
        ThemeModeDialog(
            current = themeMode,
            onSelect = onThemeModeChange,
            onDismiss = { showThemeDialog = false },
        )
    }
    if (showIconDialog) {
        IconStyleDialog(
            current = iconStyle,
            onSelect = onIconStyleChange,
            onDismiss = { showIconDialog = false },
        )
    }
}

@Composable
private fun SettingRow(
    title: String,
    subtitle: String,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = {
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        leadingContent = leading,
        trailingContent = trailing,
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier,
    )
}

@Composable
private fun SwitchRow(
    title: String,
    subtitle: String,
    leading: (@Composable () -> Unit)? = null,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = {
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        leadingContent = leading,
        trailingContent = {
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                enabled = enabled,
            )
        },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = if (enabled) {
            Modifier.clickable { onCheckedChange(!checked) }
        } else {
            Modifier
        },
    )
}

@Composable
private fun ThemeModeDialog(
    current: ThemeMode,
    onSelect: (ThemeMode) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Theme") },
        text = {
            Column {
                ThemeMode.entries.forEach { mode ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onSelect(mode)
                                onDismiss()
                            }
                            .padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = mode == current,
                            onClick = {
                                onSelect(mode)
                                onDismiss()
                            },
                        )
                        Spacer(Modifier.width(8.dp))
                        Column {
                            Text(mode.label)
                            Text(
                                mode.description,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}

@Composable
private fun IconStyleDialog(
    current: AppIconStyle,
    onSelect: (AppIconStyle) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Icon style") },
        text = {
            Column {
                AppIconStyle.entries.forEach { style ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onSelect(style)
                                onDismiss()
                            }
                            .padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        FingerprintBadge(style = style, size = 48.dp)
                        Spacer(Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(style.label)
                            Text(
                                style.description,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        RadioButton(
                            selected = style == current,
                            onClick = {
                                onSelect(style)
                                onDismiss()
                            },
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}

@Composable
private fun PairingHelpDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Pair a host") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "Start pairing on the host:",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = cardContainer(),
                ) {
                    Text(
                        "rba pair",
                        modifier = Modifier.padding(12.dp),
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                Text(
                    "Default: the terminal shows the code and you type it on this device. " +
                        "Add --code-entry host to have the device show the code and type it " +
                        "in the terminal.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    "The device never accepts a bare tap in device-entry mode.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Got it") }
        },
    )
}

@Composable
private fun HostDetailsDialog(
    host: HostPresentation,
    authenticatorDeviceId: String,
    reachability: HostReachability,
    onUnpair: (String) -> Boolean,
    onDismiss: () -> Unit,
) {
    var confirmUnpair by rememberSaveable { mutableStateOf(false) }
    if (!confirmUnpair) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(host.hostName) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    DialogField(
                        "Status",
                        when (reachability) {
                            HostReachability.CONNECTED -> "Connected"
                            HostReachability.AVAILABLE -> "Available on the network"
                            HostReachability.NOT_SEEN -> "Not seen recently"
                        },
                    )
                    DialogField("Host ID", host.hostId, monospace = true)
                    DialogField("Key ID", host.keyId, monospace = true)
                    DialogField(
                        "Certificate",
                        if (host.certificatePinned) "Pinned" else "Not pinned",
                    )
                    Text(
                        "Authentication requests from this host are accepted only after " +
                            "a strong biometric check.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) { Text("Close") }
            },
            confirmButton = {
                TextButton(
                    onClick = { confirmUnpair = true },
                    colors = androidx.compose.material3.ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Text("Unpair")
                }
            },
        )
    } else {
        AlertDialog(
            onDismissRequest = { confirmUnpair = false },
            title = { Text("Unpair ${host.hostName}?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        "This removes the host key and certificate pin from this device. " +
                            "Requests from this host will be refused immediately.",
                    )
                    Text(
                        "Authentication is disabled locally first. Host-side revocation is retried when the host is reachable.",
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmUnpair = false }) { Text("Cancel") }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onUnpair(host.hostId)
                        confirmUnpair = false
                        onDismiss()
                    },
                    colors = androidx.compose.material3.ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Text("Unpair")
                }
            },
        )
    }
}

@Composable
private fun DialogField(label: String, value: String, monospace: Boolean = false) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = if (monospace) FontFamily.Monospace else null,
        )
    }
}

// ---------------------------------------------------------------------------
// Operator-facing screens (requests and pairing)
// ---------------------------------------------------------------------------

@Composable
private fun OperatorContent(
    state: ScreenState,
    iconStyle: AppIconStyle,
    onConfirmPairing: (String?) -> Boolean,
    onRejectPairing: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .imePadding()
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            FingerprintBadge(style = iconStyle, size = 36.dp)
            Spacer(Modifier.width(12.dp))
            Text(
                "Remote authenticator",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        when (state) {
            is ScreenState.AwaitingApproval -> RequestPanel(state, waitingForBiometric = false)
            is ScreenState.AwaitingBiometric -> RequestPanel(state, waitingForBiometric = true)
            is ScreenState.PairingAwaitingCode -> PairingWaitingPanel(state.hostName)
            is ScreenState.PairingAwaitingHostCode -> PairingHostCodePanel(
                hostName = state.hostName,
                code = state.code,
            )
            is ScreenState.PairingAwaitingConfirmation -> PairingCodeEntryPanel(
                hostName = state.hostName,
                onSubmit = onConfirmPairing,
                onCancel = onRejectPairing,
            )
            is ScreenState.PairingAwaitingApproval -> PairingHostCodePanel(
                hostName = state.hostName,
                code = state.code,
                onAllow = { onConfirmPairing(null) },
                onCancel = onRejectPairing,
            )
            is ScreenState.Approved -> ApprovedPanel(state)
            is ScreenState.Denied -> DeniedPanel(state)
            is ScreenState.PairingFinalizing -> InfoPanel(
                "Completing pairing",
                "Waiting for the host to confirm enrollment.",
            )
            is ScreenState.PairingConfirmed -> InfoPanel(
                "Pairing complete",
                "This host can now request authentication.",
            )
            is ScreenState.Failed -> FailurePanel(state)
            ScreenState.Idle -> Unit
        }
    }
}

@Composable
private fun RequestPanel(state: ScreenState.AwaitingApproval, waitingForBiometric: Boolean) {
    RequestPanel(
        request = state.request,
        hostName = state.hostName,
        hostKeyId = state.hostKeyId,
        waitingForBiometric = waitingForBiometric,
    )
}

@Composable
private fun RequestPanel(state: ScreenState.AwaitingBiometric, waitingForBiometric: Boolean) {
    RequestPanel(
        request = state.request,
        hostName = state.hostName,
        hostKeyId = state.hostKeyId,
        waitingForBiometric = waitingForBiometric,
    )
}

@Composable
private fun RequestPanel(
    request: RequestPresentation,
    hostName: String,
    hostKeyId: String,
    waitingForBiometric: Boolean,
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            "Authentication request",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Field("Host", hostName)
                Field("Host key", hostKeyId.take(16))
                Field("User", request.username)
                Field("Service", request.service)
                Field("Operation", request.operation)
                Field("Action", request.purpose)
            }
        }

        // The display name and detail are advisory fields: they are not covered
        // by the device signature. Show them separately, never as the host's
        // identity, and prefer the locally stored paired name above.
        request.displayDetail?.let { detail ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(
                    containerColor = cardContainer(),
                ),
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    Icon(
                        Icons.Filled.Info,
                        contentDescription = "Unverified detail",
                        tint = MaterialTheme.colorScheme.primary,
                    )
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text(
                            "Unverified detail from the host (not covered by the signature)",
                            style = MaterialTheme.typography.labelMedium,
                        )
                        Text(detail, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.Fingerprint,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.width(8.dp))
            Text(
                if (waitingForBiometric) {
                    "Waiting for your fingerprint…"
                } else {
                    "Confirm with your fingerprint."
                },
                style = MaterialTheme.typography.bodyLarge,
            )
        }
        Text(
            "Closing the prompt, pressing back, or leaving the app denies this request.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun Field(label: String, value: String) {
    Row {
        Text(
            "$label:",
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = 8.dp),
        )
        Text(value, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun PairingWaitingPanel(hostName: String) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            "Pairing request",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            "Waiting for the host to confirm. The code is shown on the host " +
                "screen; this device will ask you to type it.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text("Host: $hostName", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun PairingHostCodePanel(
    hostName: String,
    code: String,
    onAllow: (() -> Unit)? = null,
    onCancel: (() -> Unit)? = null,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            if (onAllow != null) "Allow this host?" else "Pairing code",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            if (onAllow != null) {
                "The host accepted this code. Allow only if you started this pairing."
            } else {
                "Type this code in the host terminal. This device will not accept a " +
                    "simple tap."
            },
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (code.isNotEmpty()) {
        Box(
            modifier = Modifier
                .background(
                    cardContainer(),
                    RoundedCornerShape(20.dp),
                )
                .padding(horizontal = 32.dp, vertical = 20.dp),
        ) {
            Text(
                code.chunked(3).joinToString(" "),
                fontSize = 34.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
            )
        }
        }
        Text("Host: $hostName", style = MaterialTheme.typography.bodySmall)
        if (onAllow != null && onCancel != null) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Button(onClick = onAllow, modifier = Modifier.weight(1f)) {
                    Text("Allow")
                }
                OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                    Text("Cancel")
                }
            }
            Text(
                "This device will not trust the host until you allow it.",
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            Text(
                "Waiting for the host to accept the code…",
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PairingCodeEntryPanel(
    hostName: String,
    onSubmit: (String) -> Boolean,
    onCancel: () -> Unit,
) {
    var entered by remember { mutableStateOf("") }
    var wrongCode by rememberSaveable { mutableStateOf(false) }
    val focusRequester = remember { FocusRequester() }
    LaunchedEffect(Unit) { focusRequester.requestFocus() }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            "Confirm pairing",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            "Enter the six-digit code shown on the host. This device does not " +
                "display it.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text("Host: $hostName", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(
            value = entered,
            onValueChange = { value ->
                entered = value.filter { it.isDigit() }.take(6)
                wrongCode = false
            },
            label = { Text("Six-digit code") },
            singleLine = true,
            isError = wrongCode,
            supportingText = if (wrongCode) {
                { Text("That code does not match the host screen. Try again.") }
            } else {
                null
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(focusRequester),
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(
                onClick = {
                    if (!onSubmit(entered)) {
                        wrongCode = true
                        entered = ""
                    }
                },
                enabled = entered.length == 6,
                modifier = Modifier.weight(1f),
            ) {
                Text("Confirm")
            }
            OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                Text("Cancel")
            }
        }
        Text(
            "This device will not trust the host until the correct code is entered.",
            style = MaterialTheme.typography.bodySmall,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ApprovedPanel(state: ScreenState.Approved) {
    ResultCard(
        title = "Authenticated",
        body = "Signed for ${state.request.username} on ${state.hostName} " +
            "(${state.hostKeyId.take(16)}).",
        icon = Icons.Outlined.CheckCircle,
        container = MaterialTheme.colorScheme.primaryContainer,
        content = MaterialTheme.colorScheme.onPrimaryContainer,
    )
}

@Composable
private fun DeniedPanel(state: ScreenState.Denied) {
    ResultCard(
        title = "Not authorised",
        body = state.reason,
        icon = Icons.Outlined.Warning,
        container = MaterialTheme.colorScheme.errorContainer,
        content = MaterialTheme.colorScheme.onErrorContainer,
    )
}

@Composable
private fun FailurePanel(state: ScreenState.Failed) {
    ResultCard(
        title = "Error",
        body = state.message,
        icon = Icons.Outlined.Warning,
        container = MaterialTheme.colorScheme.errorContainer,
        content = MaterialTheme.colorScheme.onErrorContainer,
    )
}

@Composable
private fun InfoPanel(title: String, body: String) {
    ResultCard(
        title = title,
        body = body,
        icon = Icons.Outlined.CheckCircle,
        container = MaterialTheme.colorScheme.primaryContainer,
        content = MaterialTheme.colorScheme.onPrimaryContainer,
    )
}

@Composable
private fun ResultCard(
    title: String,
    body: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    container: Color,
    content: Color,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = container),
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Icon(icon, contentDescription = null, tint = content)
            Spacer(Modifier.width(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    color = content,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(body, style = MaterialTheme.typography.bodyMedium, color = content)
            }
        }
    }
}

private fun keyLocationLabel(capabilities: SecurityPresentation?): String =
    when (capabilities?.location) {
        KeyStoragePresentation.STRONGBOX -> "StrongBox"
        KeyStoragePresentation.HARDWARE -> "Hardware-backed Keystore"
        KeyStoragePresentation.SOFTWARE -> "Software Keystore"
        null -> "Unknown"
    }
