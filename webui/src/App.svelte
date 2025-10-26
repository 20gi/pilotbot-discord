<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import OverviewTab from './lib/components/OverviewTab.svelte'
  import PresenceTab from './lib/components/PresenceTab.svelte'
  import SyncTab from './lib/components/SyncTab.svelte'
  import TrackingTab from './lib/components/TrackingTab.svelte'
  import AccessTab from './lib/components/AccessTab.svelte'
  import PilotTab from './lib/components/PilotTab.svelte'
  import PilotChatTab from './lib/components/PilotChatTab.svelte'
  import CustomizationTab from './lib/components/CustomizationTab.svelte'
  import { theme, defaultTheme, setThemeSettings } from './lib/stores/theme'
  import type { ThemeSettings } from './lib/stores/theme'

  type AlertType = 'success' | 'error' | 'info'

  interface Alert {
    id: number
    type: AlertType
    message: string
  }

  interface SessionInfo {
    authenticated: boolean
    user?: { id: string; name: string }
    permissions: string[]
  }

  const TAB_DEFS = [
    { id: 'overview', label: 'Overview', required: ['view'] },
    {
      id: 'presence',
      label: 'Presence & Bio',
      required: ['view', 'set_status', 'set_online_status', 'clear_status', 'update_bio', 'send_message'],
    },
    { id: 'sync', label: 'Owner Sync', required: ['sync_view', 'sync_manage'] },
    { id: 'tracking', label: 'Tracking', required: ['tracking_view', 'tracking_manage'] },
    { id: 'pilot', label: 'Pilot Config', required: ['pilot_view', 'pilot_manage'] },
    { id: 'pilot-chat', label: 'Pilot Chat', required: ['pilot_chat'] },
    { id: 'customization', label: 'Customization', required: ['admin'] },
    { id: 'access', label: 'Access Control', required: ['admin'] },
  ] as const

  const statusTypes = [
    { value: 'playing', label: 'Playing' },
    { value: 'watching', label: 'Watching' },
    { value: 'listening', label: 'Listening' },
    { value: 'streaming', label: 'Streaming' },
    { value: 'competing', label: 'Competing' },
  ]

  const onlineStatusOptions = [
    { value: 'online', label: 'Online' },
    { value: 'idle', label: 'Idle' },
    { value: 'dnd', label: 'Do Not Disturb' },
    { value: 'invisible', label: 'Invisible' },
  ]

  const pilotStyleOptions = [
    { value: 'default', label: 'Default' },
    { value: 'secretmode', label: 'Secret Mode' },
  ]

  const panelClass = 'panel-surface border shadow-glass rounded-3xl p-6 md:p-8'
  const cardClass = 'panel-card border rounded-2xl p-5 shadow-glass'
  const navActiveClass =
    'px-4 py-2 rounded-2xl border-accent bg-accent/20 text-white shadow-glass transition text-sm font-medium'
  const navInactiveClass =
    'px-4 py-2 rounded-2xl border-white/10 bg-white/5 text-white/60 hover:text-white/90 hover:border-white/30 transition text-sm font-medium'
  const navDisabledClass =
    'px-4 py-2 rounded-2xl border-white/5 bg-white/5 text-white/30 opacity-40 cursor-not-allowed transition text-sm font-medium'

  const loginUrl = '/login'
  const logoutUrl = '/logout'

  let activeTab = 'overview'
  let session: SessionInfo = { authenticated: false, permissions: [] }
  let loadingSession = true
  let alerts: Alert[] = []
  let csrfToken: string | null = null
  let csrfTokenPromise: Promise<string> | null = null

  let statusData: any = null
  let syncData: any = null
  let trackingStatus: any = null
  let trackingLeaderboard: any[] = []
  let pilotState: any = null
  let permissionsData: { id: string; permissions: string[] }[] = []
  let permissionsDraft: Record<string, string[]> = {}
  let availablePermissions: string[] = []
  let themeSettings: ThemeSettings = { ...defaultTheme }
  const unsubscribeTheme = theme.subscribe((value) => {
    themeSettings = value
  })
  function hasPerm(perm: string): boolean {
    const perms = session.permissions ?? []
    return perms.includes('admin') || perms.includes(perm)
  }

  function hasAny(perms: readonly string[]): boolean {
    if (!perms || perms.length === 0) {
      return true
    }
    return perms.some((perm) => hasPerm(perm))
  }

  function availableTabs() {
    return TAB_DEFS.filter((tab) => hasAny(tab.required))
  }

  function ensureActiveTab() {
    if (!session.authenticated) {
      activeTab = 'overview'
      return
    }
    const allowed = availableTabs()
    if (allowed.length === 0) {
      activeTab = 'overview'
      return
    }
    if (!allowed.some((tab) => tab.id === activeTab)) {
      activeTab = allowed[0].id
    }
  }

  function addAlert(type: AlertType, message: string) {
    const id = Date.now() + Math.random()
    alerts = [...alerts, { id, type, message }]
    setTimeout(() => {
      alerts = alerts.filter((alert) => alert.id !== id)
    }, 5200)
  }

  function alertClass(type: AlertType): string {
    if (type === 'success') {
      return 'border-emerald-400/40 bg-emerald-400/10 text-emerald-100'
    }
    if (type === 'error') {
      return 'border-rose-500/50 bg-rose-500/10 text-rose-100'
    }
    return 'border-sky-400/40 bg-sky-400/10 text-sky-100'
  }

  function normalizePermOrder(perms: string[]): string[] {
    if (!perms || perms.length === 0) return []
    const unique: string[] = []
    for (const perm of perms) {
      const text = perm.trim()
      if (text && !unique.includes(text)) {
        unique.push(text)
      }
    }
    if (unique.length <= 1) return unique
    const order = new Map(availablePermissions.map((perm, index) => [perm, index]))
    const fallback = availablePermissions.length + 100
    return unique.sort((a, b) => {
      const ai = order.has(a) ? order.get(a)! : fallback
      const bi = order.has(b) ? order.get(b)! : fallback
      if (ai !== bi) return ai - bi
      return a.localeCompare(b)
    })
  }

  function setDraftPermissions(userId: string, perms: string[]) {
    permissionsDraft = { ...permissionsDraft, [userId]: normalizePermOrder(perms) }
  }

  function toggleExistingPermission(userId: string, perm: string, enabled: boolean) {
    const current = permissionsDraft[userId] ? [...permissionsDraft[userId]] : []
    const idx = current.indexOf(perm)
    if (enabled && idx === -1) {
      current.push(perm)
    } else if (!enabled && idx !== -1) {
      current.splice(idx, 1)
    }
    setDraftPermissions(userId, current)
  }

  function resetCsrfState() {
    csrfToken = null
    csrfTokenPromise = null
  }

  async function ensureCsrfToken(): Promise<string> {
    if (!session.authenticated) {
      resetCsrfState()
      throw new Error('Authentication required')
    }

    if (csrfToken) {
      return csrfToken
    }

    if (!csrfTokenPromise) {
      csrfTokenPromise = (async () => {
        try {
          const response = await fetch('/api/csrf', { credentials: 'include' })
          if (!response.ok) {
            if (response.status === 401) {
              throw new Error('Authentication required')
            }
            throw new Error('Failed to fetch CSRF token')
          }
          const data = await response.json().catch(() => ({}))
          const token = typeof data?.csrf_token === 'string' ? data.csrf_token : ''
          if (!token) {
            throw new Error('Invalid CSRF token response')
          }
          csrfToken = token
          return token
        } catch (error) {
          csrfToken = null
          throw error
        } finally {
          csrfTokenPromise = null
        }
      })()
    }

    const promise = csrfTokenPromise
    if (!promise) {
      resetCsrfState()
      throw new Error('Failed to resolve CSRF token')
    }
    const token = await promise
    if (!token) {
      resetCsrfState()
      throw new Error('Missing CSRF token')
    }
    return token
  }

  async function apiFetch(path: string, options: RequestInit = {}) {
    const opts: RequestInit = { credentials: 'include', ...options }
    const headers = new Headers(opts.headers as HeadersInit | undefined)
    const method = (opts.method ?? 'GET').toUpperCase()
    if (opts.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json')
    }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      if (!headers.has('X-CSRF-Token')) {
        const token = await ensureCsrfToken()
        headers.set('X-CSRF-Token', token)
      }
    }
    opts.method = method
    opts.headers = headers
    const response = await fetch(path, opts)
    const contentType = response.headers.get('content-type') ?? ''
    let data: any = null
    if (contentType.includes('application/json')) {
      data = await response.json()
    } else if (contentType.includes('text/')) {
      data = await response.text()
    }

    if (!response.ok) {
      if (response.status === 403 && typeof data === 'object' && data?.error === 'csrf_validation_failed') {
        csrfToken = null
      }
      const message = typeof data === 'object' && data?.error ? data.error : typeof data === 'string' && data ? data : response.statusText
      throw new Error(message)
    }

    return data
  }

  async function runSafe(fn: () => Promise<void>, label: string) {
    try {
      await fn()
    } catch (error) {
      console.error(error)
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', label + (message ? ': ' + message : ''))
    }
  }

  async function loadThemeSettings() {
    try {
      const response = await fetch('/api/theme', { credentials: 'include' })
      if (!response.ok) {
        throw new Error('failed_to_fetch_theme')
      }
      const data = await response.json().catch(() => ({}))
      const payload = data?.theme
      if (payload && typeof payload === 'object') {
        setThemeSettings({ ...defaultTheme, ...(payload as Partial<ThemeSettings>) })
      }
    } catch (error) {
      console.warn('Failed to load theme settings', error)
    }
  }

  async function saveThemeSettings(themeInput: ThemeSettings): Promise<boolean> {
    const surfaceOpacity = Number(themeInput.panel_surface_opacity)
    const cardOpacity = Number(themeInput.panel_card_opacity)
    const payload: ThemeSettings = {
      ...themeInput,
      background_image: (themeInput.background_image ?? '').trim(),
      background_color: themeInput.background_color,
      accent_color: themeInput.accent_color,
      accent_secondary_color: themeInput.accent_secondary_color,
      accent_warning_color: themeInput.accent_warning_color,
      accent_danger_color: themeInput.accent_danger_color,
      text_color: themeInput.text_color,
      panel_surface_color: themeInput.panel_surface_color,
      panel_surface_opacity: Number.isFinite(surfaceOpacity) ? Math.min(1, Math.max(0, surfaceOpacity)) : 0,
      panel_card_color: themeInput.panel_card_color,
      panel_card_opacity: Number.isFinite(cardOpacity) ? Math.min(1, Math.max(0, cardOpacity)) : 0,
      background_blur: Math.round(Math.max(0, Math.min(64, Number(themeInput.background_blur) || 0))),
      panel_blur: Math.round(Math.max(0, Math.min(64, Number(themeInput.panel_blur) || 0))),
    }
    if (!payload.background_image) {
      payload.background_image = ''
    }
    try {
      const response = await apiFetch('/api/admin/theme', {
        method: 'POST',
        body: JSON.stringify(payload),
      })
      const updated = response?.theme
      if (updated && typeof updated === 'object') {
        setThemeSettings({ ...defaultTheme, ...(updated as Partial<ThemeSettings>) })
      }
      addAlert('success', 'Theme updated')
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to update theme: ' + message)
      return false
    }
  }

  async function refreshSession() {
    loadingSession = true
    try {
      const data = await apiFetch('/api/session')
      session = {
        authenticated: Boolean(data?.authenticated),
        user: data?.user,
        permissions: data?.permissions ?? [],
      }
      if (session.authenticated) {
        try {
          await ensureCsrfToken()
        } catch (error) {
          console.error(error)
          addAlert('error', 'Failed to fetch CSRF token')
        }
      } else {
        resetCsrfState()
      }
    } catch (error) {
      session = { authenticated: false, permissions: [] }
      resetCsrfState()
    } finally {
      loadingSession = false
      ensureActiveTab()
    }
  }

  async function refreshStatus() {
    statusData = await apiFetch('/api/status')
  }

  async function refreshSyncStatus() {
    syncData = await apiFetch('/api/sync/status')
  }

  async function refreshTracking() {
    const [status, leaderboard] = await Promise.all([
      apiFetch('/api/tracking/status'),
      apiFetch('/api/tracking/leaderboard'),
    ])
    trackingStatus = status
    trackingLeaderboard = leaderboard?.leaderboard ?? []
  }

  async function refreshPilotState() {
    pilotState = await apiFetch('/api/pilot/state')
  }

  async function refreshPermissions() {
    const data = await apiFetch('/api/admin/permissions')
    availablePermissions = data?.available_permissions ?? []
    permissionsData = data?.users ?? []
    const draft: Record<string, string[]> = {}
    for (const entry of permissionsData) {
      const perms = Array.isArray(entry.permissions) ? entry.permissions : []
      draft[entry.id] = normalizePermOrder(perms)
    }
    permissionsDraft = draft
  }

  async function refreshAll() {
    await loadThemeSettings()
    await refreshSession()
    if (!session.authenticated) return

    const tasks: Promise<void>[] = []
    if (hasPerm('view')) tasks.push(runSafe(refreshStatus, 'Failed to load bot status'))
    if (hasAny(['sync_view', 'sync_manage'])) tasks.push(runSafe(refreshSyncStatus, 'Failed to load sync status'))
    if (hasAny(['tracking_view', 'tracking_manage'])) tasks.push(runSafe(refreshTracking, 'Failed to load tracking data'))
    if (hasAny(['pilot_view', 'pilot_manage', 'pilot_chat'])) tasks.push(runSafe(refreshPilotState, 'Failed to load pilot state'))
    if (hasPerm('admin')) tasks.push(runSafe(refreshPermissions, 'Failed to load access control data'))
    await Promise.all(tasks)
  }

  onMount(async () => {
    await refreshAll()
  })

  onDestroy(() => {
    unsubscribeTheme()
  })

  async function submitStatus(form: { type: string; text: string }): Promise<boolean> {
    const text = form.text.trim()
    if (!text) {
      addAlert('error', 'Status text is required')
      return false
    }
    try {
      await apiFetch('/api/set_status', {
        method: 'POST',
        body: JSON.stringify({ type: form.type, text }),
      })
      addAlert('success', 'Activity updated')
      await runSafe(refreshStatus, 'Failed to refresh status')
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to set status: ' + message)
      return false
    }
  }

  async function submitOnlineStatus(status: string): Promise<boolean> {
    try {
      await apiFetch('/api/set_online', {
        method: 'POST',
        body: JSON.stringify({ status }),
      })
      addAlert('success', 'Presence updated')
      await runSafe(refreshStatus, 'Failed to refresh status')
      await runSafe(refreshSyncStatus, 'Failed to refresh sync status')
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to change presence: ' + message)
      return false
    }
  }

  async function clearStatus(): Promise<boolean> {
    try {
      await apiFetch('/api/clear_status', { method: 'POST' })
      addAlert('success', 'Activity cleared')
      await runSafe(refreshStatus, 'Failed to refresh status')
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to clear activity: ' + message)
      return false
    }
  }

  async function updateBio(bioInput: string): Promise<boolean> {
    const bio = bioInput.trim()
    if (!bio) {
      addAlert('error', 'Bio text is required')
      return false
    }
    try {
      await apiFetch('/api/update_bio', {
        method: 'POST',
        body: JSON.stringify({ bio }),
      })
      addAlert('success', 'Bio updated successfully')
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to update bio: ' + message)
      return false
    }
  }

  async function sendDiscordMessage(payload: { channelId: string; content: string }): Promise<boolean> {
    const channelId = payload.channelId.trim()
    const content = payload.content.trim()
    if (!channelId || !content) {
      addAlert('error', 'Channel ID and content are required')
      return false
    }
    try {
      await apiFetch('/api/message', {
        method: 'POST',
        body: JSON.stringify({ channel_id: channelId, content }),
      })
      addAlert('success', 'Message sent')
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to send message: ' + message)
      return false
    }
  }

  async function enableSync(toggle: boolean) {
    try {
      await apiFetch('/api/sync/' + (toggle ? 'enable' : 'disable'), { method: 'POST' })
      addAlert('success', toggle ? 'Owner sync enabled' : 'Owner sync disabled')
      await runSafe(refreshSyncStatus, 'Failed to refresh sync status')
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to update sync: ' + message)
    }
  }

  async function setTrackingUserId(userId: string): Promise<boolean> {
    const value = userId.trim()
    if (!value) {
      addAlert('error', 'User ID is required')
      return false
    }
    try {
      await apiFetch('/api/tracking/set_user', {
        method: 'POST',
        body: JSON.stringify({ user_id: value }),
      })
      addAlert('success', 'Now tracking user ' + value)
      await runSafe(refreshTracking, 'Failed to refresh tracking data')
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to set tracked user: ' + message)
      return false
    }
  }

  async function clearTrackingData(): Promise<boolean> {
    try {
      await apiFetch('/api/tracking/clear', { method: 'POST' })
      addAlert('success', 'Tracking data cleared')
      await runSafe(refreshTracking, 'Failed to refresh tracking data')
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to clear tracking data: ' + message)
      return false
    }
  }

  async function saveExistingPermissions(userId: string) {
    const perms = permissionsDraft[userId] ?? []
    try {
      await apiFetch('/api/admin/permissions', {
        method: 'POST',
        body: JSON.stringify({ user_id: userId, permissions: perms }),
      })
      addAlert('success', `Permissions updated for ${userId}`)
      await refreshPermissions()
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to update permissions: ' + message)
    }
  }

  async function removePermissionsUser(userId: string) {
    try {
      await apiFetch(`/api/admin/permissions/${userId}`, { method: 'DELETE' })
      addAlert('success', `Removed access for ${userId}`)
      await refreshPermissions()
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to remove permissions: ' + message)
    }
  }

  async function addPermissionsUser(userIdInput: string, permissions: string[]): Promise<boolean> {
    const userId = userIdInput.trim()
    if (!userId) {
      addAlert('error', 'User ID is required')
      return false
    }
    if (permissions.length === 0) {
      addAlert('error', 'Select at least one permission')
      return false
    }
    try {
      await apiFetch('/api/admin/permissions', {
        method: 'POST',
        body: JSON.stringify({ user_id: userId, permissions }),
      })
      addAlert('success', `Added permissions for ${userId}`)
      await refreshPermissions()
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to add user: ' + message)
      return false
    }
  }

  async function togglePilotMode(desired: boolean) {
    try {
      await apiFetch('/api/pilot/mode', {
        method: 'POST',
        body: JSON.stringify({ state: desired ? 'on' : 'off' }),
      })
      addAlert('success', desired ? 'Pilot enabled' : 'Pilot disabled')
      await runSafe(refreshPilotState, 'Failed to refresh pilot state')
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to toggle pilot: ' + message)
    }
  }

  async function updatePilotStyle(mode: string): Promise<boolean> {
    if (!mode) {
      addAlert('error', 'Select a style mode')
      return false
    }
    try {
      await apiFetch('/api/pilot/style', {
        method: 'POST',
        body: JSON.stringify({ mode }),
      })
      addAlert('success', 'Pilot style set to ' + mode)
      await runSafe(refreshPilotState, 'Failed to refresh pilot state')
      return true
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to update pilot style: ' + message)
      return false
    }
  }
</script>

<div class="min-h-screen pb-16">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
    <header class={panelClass + ' flex flex-col gap-6'}>
      <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
        <div>
          <h1 class="text-3xl md:text-4xl font-semibold text-white/90 flex items-center gap-3">
            <span class="inline-flex h-12 w-12 items-center justify-center rounded-2xl glass-chip border shadow-lg">
              👨‍✈️
            </span>
            Pilot's Cockpit
          </h1>
          <p class="text-sm md:text-base text-white/60 max-w-2xl mt-2">
            pilot bot configuragtion
          </p>
        </div>
        <div class="flex flex-wrap items-center gap-3">
          {#if session.authenticated}
            <div class="glass-chip px-4 py-2 rounded-2xl border">
              <p class="text-xs uppercase tracking-wide text-white/50">Logged in</p>
              <p class="text-white/80 font-medium">{session.user?.name ?? 'Unknown User'}</p>
            </div>
            <a
              class="px-4 py-2 rounded-xl border border-white/15 text-white/70 hover:text-white/90 hover:border-white/30 transition"
              href={logoutUrl}
            >
              Logout
            </a>
          {:else if !loadingSession}
            <a
              class="px-4 py-2 rounded-xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition"
              href={loginUrl}
            >
              Login with Discord
            </a>
          {/if}
          <button
            class="px-4 py-2 rounded-xl border border-white/10 text-white/70 hover:border-white/30 hover:text-white transition"
            on:click={() => refreshAll()}
          >
            Refresh
          </button>
        </div>
      </div>

      <div class="flex flex-wrap gap-3 text-xs text-white/50">
        <span class="glass-chip px-3 py-1 rounded-full border">
          Permissions: {session.permissions?.length ? session.permissions.join(', ') : 'none'}
        </span>
        {#if statusData?.presence?.status}
          <span class="glass-chip px-3 py-1 rounded-full border">
            Current Presence: {statusData.presence.status}
          </span>
        {/if}
        {#if statusData?.presence?.activity?.name}
          <span class="glass-chip px-3 py-1 rounded-full border">
            Activity: {statusData.presence.activity.type ?? 'custom'} • {statusData.presence.activity.name}
          </span>
        {/if}
      </div>
    </header>

    {#if alerts.length}
      <div class="space-y-2">
        {#each alerts as alert (alert.id)}
          <div class={'flex items-center justify-between gap-4 rounded-2xl border px-4 py-3 text-sm ' + alertClass(alert.type)}>
            <span>{alert.message}</span>
          </div>
        {/each}
      </div>
    {/if}

    {#if loadingSession}
      <div class={panelClass + ' flex items-center justify-center text-white/60'}>Loading session…</div>
    {:else if !session.authenticated}
      <div class={panelClass + ' text-center space-y-4 text-white/70'}>
        <h2 class="text-2xl font-semibold text-white/90">Authentication required</h2>
        <p>Sign in with Discord to access the control deck.</p>
        <a
          class="inline-flex items-center justify-center px-5 py-3 rounded-2xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition"
          href={loginUrl}
        >
          Login with Discord
        </a>
      </div>
    {:else}
      <div class={panelClass + ' space-y-6'}>
        <nav class="flex flex-wrap gap-2">
          {#each TAB_DEFS as tab (tab.id)}
            {#if hasAny(tab.required)}
              <button
                type="button"
                class={activeTab === tab.id ? navActiveClass : navInactiveClass}
                on:click={() => (activeTab = tab.id)}
              >
                {tab.label}
              </button>
            {:else}
              <button type="button" class={navDisabledClass} disabled>
                {tab.label}
              </button>
            {/if}
          {/each}
        </nav>

        <div class="space-y-6">
          {#if activeTab === 'overview'}
            <OverviewTab {cardClass} {statusData} {syncData} />
          {/if}
          {#if activeTab === 'presence'}
            <PresenceTab
              {cardClass}
              {statusTypes}
              {onlineStatusOptions}
              {hasPerm}
              {submitStatus}
              {submitOnlineStatus}
              {clearStatus}
              {updateBio}
              {sendDiscordMessage}
            />
          {/if}
          {#if activeTab === 'sync'}
            <SyncTab {cardClass} {syncData} {hasPerm} {enableSync} />
          {/if}
          {#if activeTab === 'tracking'}
            <TrackingTab
              {cardClass}
              {trackingStatus}
              {trackingLeaderboard}
              {hasPerm}
              {setTrackingUserId}
              {clearTrackingData}
            />
          {/if}
          {#if activeTab === 'customization'}
            <CustomizationTab
              {cardClass}
              currentTheme={themeSettings}
              {defaultTheme}
              saveTheme={saveThemeSettings}
            />
          {/if}
          {#if activeTab === 'access'}
            <AccessTab
              {cardClass}
              {availablePermissions}
              {permissionsData}
              {permissionsDraft}
              {toggleExistingPermission}
              {saveExistingPermissions}
              {removePermissionsUser}
              {addPermissionsUser}
              {normalizePermOrder}
            />
          {/if}
          {#if activeTab === 'pilot'}
            <PilotTab
              {cardClass}
              {pilotState}
              {pilotStyleOptions}
              {hasPerm}
              {togglePilotMode}
              {updatePilotStyle}
            />
          {/if}
          {#if activeTab === 'pilot-chat'}
            <PilotChatTab
              {cardClass}
              {pilotState}
              {apiFetch}
              {addAlert}
            />
          {/if}
        </div>
      </div>
    {/if}
  </div>
</div>
