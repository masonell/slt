package dev.slt.android

import android.Manifest
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import androidx.activity.compose.BackHandler
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private lateinit var profileRepository: ProfileRepository

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startVpnService()
            } else {
                SltVpnStatusBus.update(VpnStatus.PermissionRequired, "VPN permission denied")
            }
        }

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            prepareVpnAndStart()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        profileRepository = ProfileRepository(applicationContext)

        setContent {
            SltApp(
                profileRepository = profileRepository,
                onStart = ::requestStart,
                onStop = ::stopVpnService,
            )
        }
    }

    private fun requestStart() {
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }

        prepareVpnAndStart()
    }

    private fun prepareVpnAndStart() {
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            SltVpnStatusBus.update(VpnStatus.PermissionRequired)
            vpnPermissionLauncher.launch(permissionIntent)
            return
        }

        startVpnService()
    }

    private fun startVpnService() {
        val intent = SltVpnService.startIntent(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ContextCompat.startForegroundService(this, intent)
        } else {
            startService(intent)
        }
    }

    private fun stopVpnService() {
        startService(SltVpnService.stopIntent(this))
    }
}

@Composable
private fun SltApp(
    profileRepository: ProfileRepository,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    val vpnState by SltVpnStatusBus.state.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var screen by remember { mutableStateOf<AppScreen>(AppScreen.Main) }
    var profileState by remember { mutableStateOf<ProfileStoreState?>(null) }
    var message by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        profileState = profileRepository.loadState()
    }

    BackHandler(enabled = screen != AppScreen.Main) {
        screen = when (screen) {
            AppScreen.Main -> AppScreen.Main
            AppScreen.Profiles -> AppScreen.Main
            is AppScreen.EditProfile -> AppScreen.Profiles
        }
        message = null
    }

    MaterialTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background,
        ) {
            when (val currentScreen = screen) {
                AppScreen.Main -> MainScreen(
                    vpnState = vpnState,
                    profileState = profileState,
                    message = message,
                    canStop = context.canStopVpn(vpnState.status),
                    onStart = onStart,
                    onStop = onStop,
                    onOpenProfiles = {
                        message = null
                        screen = AppScreen.Profiles
                    },
                )

                AppScreen.Profiles -> ProfilesScreen(
                    profileState = profileState,
                    message = message,
                    onAdd = {
                        message = null
                        screen = AppScreen.EditProfile(null)
                    },
                    onEdit = { id ->
                        message = null
                        screen = AppScreen.EditProfile(id)
                    },
                    onSelect = { id ->
                        scope.launch {
                            profileRepository.setActiveProfileId(id)
                            profileState = profileRepository.loadState()
                            message = "Active profile changed"
                        }
                    },
                    onDuplicate = { id ->
                        scope.launch {
                            val profile = profileRepository.duplicateProfile(id)
                            profileState = profileRepository.loadState()
                            message = profile?.let { "Duplicated ${it.metadata.name}" }
                                ?: "Profile not found"
                        }
                    },
                    onDelete = { id ->
                        scope.launch {
                            profileRepository.deleteProfile(id)
                            profileState = profileRepository.loadState()
                            message = "Profile deleted"
                        }
                    },
                )

                is AppScreen.EditProfile -> ProfileEditorScreen(
                    profileRepository = profileRepository,
                    profileId = currentScreen.profileId,
                    onSaved = {
                        scope.launch {
                            profileState = profileRepository.loadState()
                            message = "Profile saved"
                            screen = AppScreen.Profiles
                        }
                    },
                    onCancel = {
                        message = null
                        screen = AppScreen.Profiles
                    },
                )
            }
        }
    }
}

@Composable
private fun MainScreen(
    vpnState: VpnUiState,
    profileState: ProfileStoreState?,
    message: String?,
    canStop: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onOpenProfiles: () -> Unit,
) {
    val activeProfile = profileState?.activeProfile
    val canStart = activeProfile != null &&
        vpnState.status != VpnStatus.Starting &&
        vpnState.status != VpnStatus.Running

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        Text(
            text = "SLT",
            style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onOpenProfiles),
        ) {
            Text(
                text = "Active profile",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = activeProfile?.metadata?.name ?: "No active profile",
                style = MaterialTheme.typography.titleLarge,
            )
        }
        Column {
            Text(
                text = statusLabel(vpnState),
                style = MaterialTheme.typography.titleMedium,
            )
            vpnState.detail?.let { detail ->
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = detail,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        message?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(
                onClick = onStart,
                enabled = canStart,
                modifier = Modifier.weight(1f),
            ) {
                Text("Connect")
            }
            OutlinedButton(
                onClick = onStop,
                enabled = canStop,
                modifier = Modifier.weight(1f),
            ) {
                Text("Disconnect")
            }
        }
    }
}

@Composable
private fun ProfilesScreen(
    profileState: ProfileStoreState?,
    message: String?,
    onAdd: () -> Unit,
    onEdit: (String) -> Unit,
    onSelect: (String) -> Unit,
    onDuplicate: (String) -> Unit,
    onDelete: (String) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Profiles",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Button(onClick = onAdd) {
            Text("Add Profile")
        }
        message?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }

        val profiles = profileState?.profiles.orEmpty()
        if (profiles.isEmpty()) {
            Text(
                text = "No profiles",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        profiles.forEach { profile ->
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                HorizontalDivider()
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = profile.name,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            text = if (profile.isActive) "Active" else "Inactive",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (!profile.isActive) {
                        TextButton(onClick = { onSelect(profile.id) }) {
                            Text("Use")
                        }
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { onEdit(profile.id) }) {
                        Text("Edit")
                    }
                    OutlinedButton(onClick = { onDuplicate(profile.id) }) {
                        Text("Duplicate")
                    }
                    OutlinedButton(onClick = { onDelete(profile.id) }) {
                        Text("Delete")
                    }
                }
            }
        }
    }
}

@Composable
private fun ProfileEditorScreen(
    profileRepository: ProfileRepository,
    profileId: String?,
    onSaved: () -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var loadedProfile by remember(profileId) { mutableStateOf<SltProfile?>(null) }
    var name by remember(profileId) { mutableStateOf("") }
    var toml by remember(profileId) { mutableStateOf("") }
    var routeText by remember(profileId) { mutableStateOf("") }
    var dnsMode by remember(profileId) { mutableStateOf(DnsMode.System) }
    var dnsText by remember(profileId) { mutableStateOf("") }
    var appMode by remember(profileId) { mutableStateOf(AppVpnMode.All) }
    var appPackageNames by remember(profileId) { mutableStateOf(emptyList<String>()) }
    var testUrlsText by remember(profileId) { mutableStateOf("") }
    var validation by remember(profileId) { mutableStateOf<ConfigValidationResult?>(null) }
    var message by remember(profileId) { mutableStateOf<String?>(null) }
    var routeMessage by remember(profileId) { mutableStateOf<String?>(null) }
    var dnsMessage by remember(profileId) { mutableStateOf<String?>(null) }
    var appMessage by remember(profileId) { mutableStateOf<String?>(null) }
    var testUrlsMessage by remember(profileId) { mutableStateOf<String?>(null) }
    var editingRoutes by remember(profileId) { mutableStateOf(false) }
    var editingDns by remember(profileId) { mutableStateOf(false) }
    var editingApps by remember(profileId) { mutableStateOf(false) }
    var editingTestUrls by remember(profileId) { mutableStateOf(false) }

    LaunchedEffect(profileId) {
        val profile = profileId?.let { profileRepository.loadProfile(it) }
        loadedProfile = profile
        name = profile?.metadata?.name.orEmpty()
        toml = profile?.clientToml.orEmpty()
        routeText = exportVpnRouteRules(profile?.metadata?.routes.orEmpty())
        dnsMode = profile?.metadata?.dns?.mode ?: DnsMode.System
        dnsText = exportDnsServers(profile?.metadata?.dns?.servers.orEmpty())
        appMode = profile?.metadata?.appRules?.mode ?: AppVpnMode.All
        appPackageNames = profile?.metadata?.appRules?.packageNames.orEmpty()
        testUrlsText = exportTestUrls(profile?.metadata?.testUrls.orEmpty())
        validation = null
        message = null
        routeMessage = null
        dnsMessage = null
        appMessage = null
        testUrlsMessage = null
        editingRoutes = false
        editingDns = false
        editingApps = false
        editingTestUrls = false
    }

    BackHandler(enabled = editingRoutes || editingDns || editingApps || editingTestUrls) {
        editingRoutes = false
        editingDns = false
        editingApps = false
        editingTestUrls = false
    }

    fun validate(): ConfigValidationResult {
        val result = SltNative.validateClientConfig(toml)
        validation = result
        message = if (result.isValid) "Config is valid" else result.error
        return result
    }

    fun parseRoutesForSave(): List<VpnRouteRule>? =
        try {
            val routes = parseVpnRouteRules(routeText)
            if (routes.isEmpty()) {
                routeMessage = "At least one VPN route is required"
                message = routeMessage
                null
            } else {
                routeText = exportVpnRouteRules(routes)
                routeMessage = "${routes.size} route${if (routes.size == 1) "" else "s"} ready"
                routes
            }
        } catch (error: IllegalArgumentException) {
            routeMessage = error.message ?: "Invalid routes"
            message = routeMessage
            null
        }

    fun parseDnsForSave(routes: List<VpnRouteRule>?): DnsSettings? =
        try {
            val dns = parseDnsSettings(dnsMode, dnsText)
            dnsText = exportDnsServers(dns.servers)
            val warnings = routes?.let { dnsExcludedRouteWarnings(it, dns) }.orEmpty()
            dnsMessage = warnings.firstOrNull()
                ?: when (dns.mode) {
                    DnsMode.System -> "System DNS ready"
                    DnsMode.Custom -> "${dns.servers.size} DNS server${if (dns.servers.size == 1) "" else "s"} ready"
                }
            dns
        } catch (error: IllegalArgumentException) {
            dnsMessage = error.message ?: "Invalid DNS settings"
            message = dnsMessage
            null
        }

    fun parseAppsForSave(): AppVpnRules? =
        try {
            val appRules = normalizeAppVpnRules(appMode, appPackageNames, context.packageName)
            appMode = appRules.mode
            appPackageNames = appRules.packageNames
            appMessage = appRulesSummary(appRules)
            appRules
        } catch (error: IllegalArgumentException) {
            appMessage = error.message ?: "Invalid app rules"
            message = appMessage
            null
        }

    fun parseTestUrlsForSave(): List<String>? =
        try {
            val testUrls = parseTestUrls(testUrlsText)
            testUrlsText = exportTestUrls(testUrls)
            testUrlsMessage = if (testUrls.isEmpty()) {
                "No test URLs configured"
            } else {
                "${testUrls.size} test URL${if (testUrls.size == 1) "" else "s"} ready"
            }
            testUrls
        } catch (error: IllegalArgumentException) {
            testUrlsMessage = error.message ?: "Invalid test URLs"
            message = testUrlsMessage
            null
        }

    if (editingRoutes) {
        RouteEditorScreen(
            routeText = routeText,
            routeMessage = routeMessage,
            onRouteTextChange = {
                routeText = it
                routeMessage = null
            },
            onApply = {
                val routes = parseRoutesForSave()
                if (routes != null) {
                    editingRoutes = false
                    message = null
                }
            },
            onCopy = {
                try {
                    val routes = parseVpnRouteRules(routeText)
                    val normalizedRoutes = exportVpnRouteRules(routes)
                    routeText = normalizedRoutes
                    context.copySensitiveText("SLT routes", normalizedRoutes)
                    routeMessage = "Routes copied"
                } catch (error: IllegalArgumentException) {
                    routeMessage = error.message ?: "Invalid routes"
                }
            },
            onCancel = {
                editingRoutes = false
            },
        )
        return
    }

    if (editingDns) {
        DnsEditorScreen(
            dnsMode = dnsMode,
            dnsText = dnsText,
            dnsMessage = dnsMessage,
            onDnsModeChange = {
                dnsMode = it
                dnsMessage = null
            },
            onDnsTextChange = {
                dnsText = it
                dnsMessage = null
            },
            onApply = {
                val routes = try {
                    parseVpnRouteRules(routeText)
                } catch (_: IllegalArgumentException) {
                    null
                }
                if (parseDnsForSave(routes) != null) {
                    editingDns = false
                    message = null
                }
            },
            onCancel = {
                editingDns = false
            },
        )
        return
    }

    if (editingApps) {
        AppRulesEditorScreen(
            appMode = appMode,
            selectedPackageNames = appPackageNames,
            appMessage = appMessage,
            ownPackageName = context.packageName,
            onAppModeChange = {
                appMode = it
                appMessage = null
            },
            onSelectedPackageNamesChange = {
                appPackageNames = it
                appMessage = null
            },
            onApply = {
                if (parseAppsForSave() != null) {
                    editingApps = false
                    message = null
                }
            },
            onCancel = {
                editingApps = false
            },
        )
        return
    }

    if (editingTestUrls) {
        TestUrlsEditorScreen(
            testUrlsText = testUrlsText,
            testUrlsMessage = testUrlsMessage,
            onTestUrlsTextChange = {
                testUrlsText = it
                testUrlsMessage = null
            },
            onApply = {
                if (parseTestUrlsForSave() != null) {
                    editingTestUrls = false
                    message = null
                }
            },
            onCancel = {
                editingTestUrls = false
            },
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = if (profileId == null) "Add Profile" else "Edit Profile",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Profile name") },
        )
        OutlinedTextField(
            value = toml,
            onValueChange = {
                toml = it
                validation = null
                message = null
            },
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            label = { Text("SLT client TOML") },
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
        validation?.summary?.let { summary ->
            Text(
                text = "Server ${summary.serverHost}:${summary.serverPort}  MTU ${summary.tunMtu}  IPv4 ${summary.assignedIpv4}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = routeSummary(routeText),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { editingRoutes = true }) {
                Text("Edit Routes")
            }
            routeMessage?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (it.contains("required") || it.contains("Line ") || it.contains("cannot")) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = dnsSummary(dnsMode, dnsText),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { editingDns = true }) {
                Text("Edit DNS")
            }
            dnsMessage?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (messageIsError(it)) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = appsSummary(appMode, appPackageNames.filterNot { it == context.packageName }),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { editingApps = true }) {
                Text("Edit Apps")
            }
            appMessage?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (messageIsError(it)) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = testUrlsSummary(testUrlsText),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { editingTestUrls = true }) {
                Text("Edit Test URLs")
            }
            testUrlsMessage?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (messageIsError(it)) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
        message?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (validation?.isValid == false || messageIsError(it)) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.primary
                },
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedButton(onClick = { validate() }) {
                Text("Validate")
            }
            Button(
                onClick = {
                    val trimmedName = name.trim()
                    if (trimmedName.isEmpty()) {
                        message = "Profile name is required"
                        return@Button
                    }
                    val result = validate()
                    if (!result.isValid) {
                        return@Button
                    }
                    val routes = parseRoutesForSave() ?: return@Button
                    val dns = parseDnsForSave(routes) ?: return@Button
                    val appRules = parseAppsForSave() ?: return@Button
                    val testUrls = parseTestUrlsForSave() ?: return@Button
                    scope.launch {
                        val metadata = (loadedProfile?.metadata ?: ProfileMetadata(name = trimmedName))
                            .copy(
                                name = trimmedName,
                                routes = routes,
                                dns = dns,
                                testUrls = testUrls,
                                appRules = appRules,
                            )
                        profileRepository.saveProfile(
                            id = profileId,
                            name = trimmedName,
                            clientToml = toml,
                            metadata = metadata,
                        )
                        onSaved()
                    }
                },
            ) {
                Text("Save")
            }
            OutlinedButton(onClick = { context.copySensitiveText("SLT config", toml) }) {
                Text("Copy")
            }
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        }
    }
}

@Composable
private fun TestUrlsEditorScreen(
    testUrlsText: String,
    testUrlsMessage: String?,
    onTestUrlsTextChange: (String) -> Unit,
    onApply: () -> Unit,
    onCancel: () -> Unit,
) {
    var newTestUrl by remember { mutableStateOf("") }
    var listMessage by remember { mutableStateOf<String?>(null) }
    val currentUrls = try {
        parseTestUrls(testUrlsText)
    } catch (_: IllegalArgumentException) {
        emptyList()
    }
    val currentMessage = listMessage ?: testUrlsMessage

    fun replaceTestUrls(urls: List<String>) {
        onTestUrlsTextChange(exportTestUrls(urls))
        listMessage = null
    }

    fun addTestUrl() {
        val candidate = newTestUrl.trim()
        if (candidate.isEmpty()) {
            listMessage = "Test URL is required"
            return
        }

        try {
            val nextUrls = parseTestUrls(
                (currentUrls + candidate).joinToString("\n"),
            )
            if (nextUrls == currentUrls) {
                listMessage = "Test URL already exists"
                return
            }
            replaceTestUrls(nextUrls)
            newTestUrl = ""
            listMessage = "Test URL added"
        } catch (error: IllegalArgumentException) {
            listMessage = error.message ?: "Invalid test URL"
        }
    }

    fun removeTestUrl(index: Int) {
        replaceTestUrls(currentUrls.filterIndexed { urlIndex, _ -> urlIndex != index })
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "Test URLs",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (currentUrls.isEmpty()) {
                item {
                    Text(
                        text = "No test URLs",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                items(currentUrls, key = { it }) { url ->
                    TestUrlListItem(
                        url = url,
                        onRemove = { removeTestUrl(currentUrls.indexOf(url)) },
                    )
                }
            }
        }
        HorizontalDivider()
        OutlinedTextField(
            value = newTestUrl,
            onValueChange = {
                newTestUrl = it
                listMessage = null
            },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("URL") },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        )
        currentMessage?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (messageIsError(it)) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.primary
                },
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedButton(onClick = ::addTestUrl) {
                Text("Add")
            }
            Button(onClick = onApply) {
                Text("Apply")
            }
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        }
    }
}

@Composable
private fun TestUrlListItem(
    url: String,
    onRemove: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HorizontalDivider()
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = url,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
            )
            TextButton(onClick = onRemove) {
                Text("Remove")
            }
        }
    }
}

@Composable
private fun DnsEditorScreen(
    dnsMode: DnsMode,
    dnsText: String,
    dnsMessage: String?,
    onDnsModeChange: (DnsMode) -> Unit,
    onDnsTextChange: (String) -> Unit,
    onApply: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "DNS",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (dnsMode == DnsMode.System) {
                Button(
                    onClick = { onDnsModeChange(DnsMode.System) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("System")
                }
                OutlinedButton(
                    onClick = { onDnsModeChange(DnsMode.Custom) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Custom")
                }
            } else {
                OutlinedButton(
                    onClick = { onDnsModeChange(DnsMode.System) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("System")
                }
                Button(
                    onClick = { onDnsModeChange(DnsMode.Custom) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Custom")
                }
            }
        }
        if (dnsMode == DnsMode.Custom) {
            OutlinedTextField(
                value = dnsText,
                onValueChange = onDnsTextChange,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                label = { Text("DNS servers") },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
        } else {
            Spacer(modifier = Modifier.weight(1f))
        }
        dnsMessage?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (messageIsError(it)) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.primary
                },
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = onApply) {
                Text("Apply")
            }
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        }
    }
}

@Composable
private fun AppRulesEditorScreen(
    appMode: AppVpnMode,
    selectedPackageNames: List<String>,
    appMessage: String?,
    ownPackageName: String,
    onAppModeChange: (AppVpnMode) -> Unit,
    onSelectedPackageNamesChange: (List<String>) -> Unit,
    onApply: () -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    var installedApps by remember { mutableStateOf<List<InstalledApp>?>(null) }
    var loadMessage by remember { mutableStateOf<String?>(null) }
    var search by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        try {
            installedApps = withContext(Dispatchers.Default) {
                loadInstalledLaunchableApps(context)
            }
        } catch (error: RuntimeException) {
            loadMessage = error.message ?: "Could not load installed apps"
            installedApps = emptyList()
        }
    }

    val effectiveSelectedPackages = when (appMode) {
        AppVpnMode.All -> emptyList()
        AppVpnMode.Allowlist -> selectedPackageNames.filterNot { it == ownPackageName }.distinct()
        AppVpnMode.Blocklist -> selectedPackageNames.filterNot { it == ownPackageName }.distinct()
    }
    val selectedPackageSet = effectiveSelectedPackages.toSet()
    val installedPackageNames = installedApps.orEmpty().map { it.packageName }.toSet() + ownPackageName
    val missingPackages = missingAppPackages(
        rules = AppVpnRules(mode = appMode, packageNames = effectiveSelectedPackages),
        installedPackages = installedPackageNames,
    )
    val visibleApps = installedApps.orEmpty()
        .filterNot { app -> app.packageName == ownPackageName }
        .filter { app ->
            search.isBlank() ||
                app.label.contains(search, ignoreCase = true) ||
                app.packageName.contains(search, ignoreCase = true)
        }
        .sortedWith(
            compareByDescending<InstalledApp> { it.packageName in selectedPackageSet }
                .thenBy { it.label.lowercase() }
                .thenBy { it.packageName },
        )
    val currentMessage = loadMessage ?: appMessage

    fun replaceSelectedPackages(packageNames: List<String>) {
        onSelectedPackageNamesChange(
            when (appMode) {
                AppVpnMode.All -> emptyList()
                AppVpnMode.Allowlist -> packageNames.distinct()
                AppVpnMode.Blocklist -> packageNames.filterNot { it == ownPackageName }.distinct()
            },
        )
    }

    fun setPackageSelected(packageName: String, selected: Boolean) {
        if (appMode == AppVpnMode.All) {
            return
        }
        if (packageName == ownPackageName) {
            return
        }

        val nextPackages = if (selected) {
            effectiveSelectedPackages + packageName
        } else {
            effectiveSelectedPackages.filterNot { it == packageName }
        }
        replaceSelectedPackages(nextPackages)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "Apps",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        AppVpnModeSelector(
            appMode = appMode,
            onAppModeChange = {
                onAppModeChange(it)
                when (it) {
                    AppVpnMode.All -> onSelectedPackageNamesChange(emptyList())
                    AppVpnMode.Allowlist -> onSelectedPackageNamesChange(selectedPackageNames.filterNot { packageName ->
                        packageName == ownPackageName
                    })
                    AppVpnMode.Blocklist -> onSelectedPackageNamesChange(selectedPackageNames.filterNot { packageName ->
                        packageName == ownPackageName
                    })
                }
            },
        )
        if (appMode != AppVpnMode.All) {
            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Search apps") },
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedButton(
                    onClick = {
                        replaceSelectedPackages(effectiveSelectedPackages + installedApps.orEmpty().map { it.packageName })
                    },
                    enabled = installedApps != null,
                ) {
                    Text("Add all")
                }
                OutlinedButton(onClick = { replaceSelectedPackages(emptyList()) }) {
                    Text("Remove all")
                }
            }
        }
        if (missingPackages.isNotEmpty()) {
            Text(
                text = "Missing saved packages: ${missingPackages.joinToString(", ")}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        currentMessage?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (messageIsError(it)) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.primary
                },
            )
        }
        if (appMode == AppVpnMode.All) {
            Spacer(modifier = Modifier.weight(1f))
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                if (installedApps == null) {
                    item {
                        Text(
                            text = "Loading apps",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else if (visibleApps.isEmpty()) {
                    item {
                        Text(
                            text = "No apps found",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else {
                    items(visibleApps, key = { it.packageName }) { app ->
                        AppListItem(
                            app = app,
                            checked = app.packageName in selectedPackageSet,
                            enabled = app.packageName != ownPackageName,
                            onCheckedChange = { selected -> setPackageSelected(app.packageName, selected) },
                        )
                    }
                }
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = onApply) {
                Text("Apply")
            }
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        }
    }
}

@Composable
private fun AppVpnModeSelector(
    appMode: AppVpnMode,
    onAppModeChange: (AppVpnMode) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppVpnMode.entries.forEach { mode ->
            if (appMode == mode) {
                Button(
                    onClick = { onAppModeChange(mode) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text(mode.label())
                }
            } else {
                OutlinedButton(
                    onClick = { onAppModeChange(mode) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text(mode.label())
                }
            }
        }
    }
}

@Composable
private fun AppListItem(
    app: InstalledApp,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HorizontalDivider()
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(enabled = enabled) { onCheckedChange(!checked) },
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(
                checked = checked,
                onCheckedChange = if (enabled) onCheckedChange else null,
                enabled = enabled,
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.label,
                    style = MaterialTheme.typography.bodyLarge,
                )
                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun RouteEditorScreen(
    routeText: String,
    routeMessage: String?,
    onRouteTextChange: (String) -> Unit,
    onApply: () -> Unit,
    onCopy: () -> Unit,
    onCancel: () -> Unit,
) {
    var editorMode by remember { mutableStateOf(RouteEditorMode.List) }
    var newRouteCidr by remember { mutableStateOf("") }
    var newRouteExcluded by remember { mutableStateOf(false) }
    var listMessage by remember { mutableStateOf<String?>(null) }
    val currentMessage = listMessage ?: routeMessage

    fun currentRoutesOrNull(): List<VpnRouteRule>? =
        try {
            parseVpnRouteRules(routeText)
        } catch (error: IllegalArgumentException) {
            listMessage = error.message ?: "Invalid routes"
            null
        }

    fun currentRoutesForDisplay(): List<VpnRouteRule>? =
        try {
            parseVpnRouteRules(routeText)
        } catch (_: IllegalArgumentException) {
            null
        }

    fun replaceRoutes(routes: List<VpnRouteRule>) {
        onRouteTextChange(exportVpnRouteRules(routes))
        listMessage = null
    }

    fun addRouteFromListForm() {
        val cidr = newRouteCidr.trim()
        if (cidr.isEmpty()) {
            listMessage = "Route CIDR is required"
            return
        }
        val prefix = if (newRouteExcluded) "!" else ""
        val existingRoutes = currentRoutesOrNull() ?: return
        val newRoutes = try {
            parseVpnRouteRules("$prefix$cidr")
        } catch (error: IllegalArgumentException) {
            listMessage = error.message ?: "Invalid route"
            return
        }
        val existingText = exportVpnRouteRules(existingRoutes)
        val candidateText = listOf(existingText, "$prefix$cidr")
            .filter { it.isNotBlank() }
            .joinToString("\n")
        try {
            val routes = parseVpnRouteRules(candidateText)
            if (routes == existingRoutes) {
                listMessage = if (newRoutes.any { route -> existingRoutes.contains(route) }) {
                    "Route already exists"
                } else {
                    "Route is already covered by an existing ${if (newRouteExcluded) "exclude" else "include"} route"
                }
                return
            }
            replaceRoutes(routes)
            newRouteCidr = ""
            listMessage = "Route added"
        } catch (error: IllegalArgumentException) {
            listMessage = error.message ?: "Invalid route"
        }
    }

    fun removeRoute(index: Int) {
        val routes = currentRoutesOrNull() ?: return
        replaceRoutes(routes.filterIndexed { routeIndex, _ -> routeIndex != index })
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "Routes",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        PrimaryTabRow(selectedTabIndex = editorMode.ordinal) {
            RouteEditorMode.entries.forEach { mode ->
                Tab(
                    selected = editorMode == mode,
                    onClick = { editorMode = mode },
                    text = { Text(mode.label) },
                )
            }
        }
        when (editorMode) {
            RouteEditorMode.List -> RouteListEditor(
                routes = currentRoutesForDisplay(),
                newRouteCidr = newRouteCidr,
                newRouteExcluded = newRouteExcluded,
                onNewRouteCidrChange = {
                    newRouteCidr = it
                    listMessage = null
                },
                onNewRouteExcludedChange = {
                    newRouteExcluded = it
                    listMessage = null
                },
                onAdd = ::addRouteFromListForm,
                onRemove = ::removeRoute,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            )

            RouteEditorMode.Text -> OutlinedTextField(
                value = routeText,
                onValueChange = {
                    onRouteTextChange(it)
                    listMessage = null
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                label = { Text("VPN routes") },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
        }
        currentMessage?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (messageIsError(it)) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.primary
                },
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = onApply) {
                Text("Apply")
            }
            OutlinedButton(onClick = onCopy) {
                Text("Copy")
            }
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        }
    }
}

@Composable
private fun RouteListEditor(
    routes: List<VpnRouteRule>?,
    newRouteCidr: String,
    newRouteExcluded: Boolean,
    onNewRouteCidrChange: (String) -> Unit,
    onNewRouteExcludedChange: (Boolean) -> Unit,
    onAdd: () -> Unit,
    onRemove: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (routes == null) {
            Text(
                text = "Fix route text before using the list view.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        } else if (routes.isEmpty()) {
            Text(
                text = "No routes",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            routes.forEachIndexed { index, route ->
                RouteListItem(
                    route = route,
                    onRemove = { onRemove(index) },
                )
            }
        }

        HorizontalDivider()
        OutlinedTextField(
            value = newRouteCidr,
            onValueChange = onNewRouteCidrChange,
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("CIDR") },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (newRouteExcluded) {
                OutlinedButton(
                    onClick = { onNewRouteExcludedChange(false) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Include")
                }
                Button(
                    onClick = { onNewRouteExcludedChange(true) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Exclude")
                }
            } else {
                Button(
                    onClick = { onNewRouteExcludedChange(false) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Include")
                }
                OutlinedButton(
                    onClick = { onNewRouteExcludedChange(true) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Exclude")
                }
            }
            Button(onClick = onAdd) {
                Text("Add")
            }
        }
    }
}

@Composable
private fun RouteListItem(
    route: VpnRouteRule,
    onRemove: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HorizontalDivider()
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (route.excluded) "Exclude" else "Include",
                    style = MaterialTheme.typography.labelLarge,
                    color = if (route.excluded) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.primary
                    },
                )
                Text(
                    text = route.cidr,
                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
            }
            TextButton(onClick = onRemove) {
                Text("Remove")
            }
        }
    }
}

private enum class RouteEditorMode(val label: String) {
    List("List"),
    Text("Text"),
}

private sealed interface AppScreen {
    data object Main : AppScreen

    data object Profiles : AppScreen

    data class EditProfile(val profileId: String?) : AppScreen
}

private fun statusLabel(state: VpnUiState): String =
    when (state.status) {
        VpnStatus.Idle -> "Idle"
        VpnStatus.PermissionRequired -> "Permission required"
        VpnStatus.Starting -> "Connecting"
        VpnStatus.Running -> "Connected"
        VpnStatus.Stopped -> "Stopped"
        VpnStatus.Error -> "Error"
    }

private fun Context.canStopVpn(status: VpnStatus): Boolean =
    status == VpnStatus.Starting || status == VpnStatus.Running

private fun Context.copySensitiveText(label: String, text: String) {
    val clipboardManager = getSystemService(ClipboardManager::class.java)
    val clip = ClipData.newPlainText(label, text)
    clip.description.extras = PersistableBundle().apply {
        putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
    }
    clipboardManager.setPrimaryClip(clip)
}

private fun routeSummary(routeText: String): String =
    try {
        val routes = parseVpnRouteRules(routeText)
        val included = routes.count { !it.excluded }
        val excluded = routes.count { it.excluded }
        "Routes: $included include, $excluded exclude"
    } catch (_: IllegalArgumentException) {
        "Routes need attention"
    }

private fun dnsSummary(mode: DnsMode, dnsText: String): String =
    try {
        val dns = parseDnsSettings(mode, dnsText)
        when (dns.mode) {
            DnsMode.System -> "DNS: system"
            DnsMode.Custom -> "DNS: ${dns.servers.size} custom server${if (dns.servers.size == 1) "" else "s"}"
        }
    } catch (_: IllegalArgumentException) {
        "DNS needs attention"
    }

private fun appsSummary(mode: AppVpnMode, packageNames: List<String>): String =
    when (mode) {
        AppVpnMode.All -> "Apps: all"
        AppVpnMode.Allowlist -> "Apps: ${packageNames.size} allowed"
        AppVpnMode.Blocklist -> "Apps: ${packageNames.size} blocked"
    }

private fun testUrlsSummary(testUrlsText: String): String =
    try {
        val testUrls = parseTestUrls(testUrlsText)
        "Tests: ${testUrls.size} URL${if (testUrls.size == 1) "" else "s"}"
    } catch (_: IllegalArgumentException) {
        "Tests need attention"
    }

private fun appRulesSummary(rules: AppVpnRules): String =
    when (rules.mode) {
        AppVpnMode.All -> "All apps ready"
        AppVpnMode.Allowlist -> "${rules.packageNames.size} allowed app${if (rules.packageNames.size == 1) "" else "s"} ready"
        AppVpnMode.Blocklist -> "${rules.packageNames.size} blocked app${if (rules.packageNames.size == 1) "" else "s"} ready"
    }

private fun AppVpnMode.label(): String =
    when (this) {
        AppVpnMode.All -> "All"
        AppVpnMode.Allowlist -> "Allowlist"
        AppVpnMode.Blocklist -> "Blocklist"
    }

private fun messageIsError(message: String): Boolean =
    message.contains("Line ") ||
        message.contains("cannot") ||
        message.contains("required") ||
        message.contains("Invalid") ||
        message.contains("not valid") ||
        message.contains("must be") ||
        message.contains("must not")
