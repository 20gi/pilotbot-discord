<script lang="ts">
  import { onMount } from 'svelte'

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

  const panelClass =
    'bg-surface-glass/80 border border-white/10 backdrop-blur-md shadow-glass rounded-3xl p-6 md:p-8'
  const cardClass =
    'bg-white/5 border border-white/10 rounded-2xl p-5 backdrop-blur-sm shadow-glass'
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

  let statusData: any = null
  let syncData: any = null
  let trackingStatus: any = null
  let trackingLeaderboard: any[] = []
  let pilotState: any = null
  let permissionsData: { id: string; permissions: string[] }[] = []
  let permissionsDraft: Record<string, string[]> = {}
  let availablePermissions: string[] = []
  let newUserId = ''
  let newUserPerms: string[] = []

  let statusForm = { type: 'playing', text: '' }
  let onlineStatus = 'online'
  let bioText = ''
  let messageForm = { channelId: '', content: '' }
  let trackingUserInput = ''
  let pilotStyleInput = 'default'

  let pilotChatHistory: { role: 'user' | 'assistant'; content: string }[] = []
  let pilotInput = ''
  let pilotChatLoading = false

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

  function toggleNewUserPermission(perm: string, enabled: boolean) {
    const current = [...newUserPerms]
    const idx = current.indexOf(perm)
    if (enabled && idx === -1) {
      current.push(perm)
    } else if (!enabled && idx !== -1) {
      current.splice(idx, 1)
    }
    newUserPerms = normalizePermOrder(current)
  }

  async function apiFetch(path: string, options: RequestInit = {}) {
    const opts: RequestInit = { credentials: 'include', ...options }
    const headers = new Headers(opts.headers as HeadersInit | undefined)
    if (opts.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json')
    }
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

  async function refreshSession() {
    loadingSession = true
    try {
      const data = await apiFetch('/api/session')
      session = {
        authenticated: Boolean(data?.authenticated),
        user: data?.user,
        permissions: data?.permissions ?? [],
      }
    } catch (error) {
      session = { authenticated: false, permissions: [] }
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
    if (pilotState?.style_mode) {
      pilotStyleInput = pilotState.style_mode
    }
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

  async function submitStatus() {
    const text = statusForm.text.trim()
    if (!text) {
      addAlert('error', 'Status text is required')
      return
    }
    try {
      await apiFetch('/api/set_status', {
        method: 'POST',
        body: JSON.stringify({ type: statusForm.type, text }),
      })
      addAlert('success', 'Activity updated')
      statusForm = { ...statusForm, text: '' }
      await runSafe(refreshStatus, 'Failed to refresh status')
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to set status: ' + message)
    }
  }

  async function submitOnlineStatus() {
    try {
      await apiFetch('/api/set_online', {
        method: 'POST',
        body: JSON.stringify({ status: onlineStatus }),
      })
      addAlert('success', 'Presence updated')
      await runSafe(refreshStatus, 'Failed to refresh status')
      await runSafe(refreshSyncStatus, 'Failed to refresh sync status')
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to change presence: ' + message)
    }
  }

  async function clearStatus() {
    try {
      await apiFetch('/api/clear_status', { method: 'POST' })
      addAlert('success', 'Activity cleared')
      await runSafe(refreshStatus, 'Failed to refresh status')
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to clear activity: ' + message)
    }
  }

  async function updateBio() {
    const bio = bioText.trim()
    if (!bio) {
      addAlert('error', 'Bio text is required')
      return
    }
    try {
      await apiFetch('/api/update_bio', {
        method: 'POST',
        body: JSON.stringify({ bio }),
      })
      addAlert('success', 'Bio updated successfully')
      bioText = ''
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to update bio: ' + message)
    }
  }

  async function sendDiscordMessage() {
    const channelId = messageForm.channelId.trim()
    const content = messageForm.content.trim()
    if (!channelId || !content) {
      addAlert('error', 'Channel ID and content are required')
      return
    }
    try {
      await apiFetch('/api/message', {
        method: 'POST',
        body: JSON.stringify({ channel_id: channelId, content }),
      })
      addAlert('success', 'Message sent')
      messageForm = { channelId: '', content: '' }
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to send message: ' + message)
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

  async function setTrackingUserId() {
    const value = trackingUserInput.trim()
    if (!value) {
      addAlert('error', 'User ID is required')
      return
    }
    try {
      await apiFetch('/api/tracking/set_user', {
        method: 'POST',
        body: JSON.stringify({ user_id: value }),
      })
      addAlert('success', 'Now tracking user ' + value)
      await runSafe(refreshTracking, 'Failed to refresh tracking data')
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to set tracked user: ' + message)
    }
  }

  async function clearTrackingData() {
    try {
      await apiFetch('/api/tracking/clear', { method: 'POST' })
      addAlert('success', 'Tracking data cleared')
      await runSafe(refreshTracking, 'Failed to refresh tracking data')
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to clear tracking data: ' + message)
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

  async function addPermissionsUser() {
    const userId = newUserId.trim()
    if (!userId) {
      addAlert('error', 'User ID is required')
      return
    }
    if (newUserPerms.length === 0) {
      addAlert('error', 'Select at least one permission')
      return
    }
    try {
      await apiFetch('/api/admin/permissions', {
        method: 'POST',
        body: JSON.stringify({ user_id: userId, permissions: newUserPerms }),
      })
      addAlert('success', `Added permissions for ${userId}`)
      newUserId = ''
      newUserPerms = []
      await refreshPermissions()
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to add user: ' + message)
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

  async function updatePilotStyle() {
    if (!pilotStyleInput) {
      addAlert('error', 'Select a style mode')
      return
    }
    try {
      await apiFetch('/api/pilot/style', {
        method: 'POST',
        body: JSON.stringify({ mode: pilotStyleInput }),
      })
      addAlert('success', 'Pilot style set to ' + pilotStyleInput)
      await runSafe(refreshPilotState, 'Failed to refresh pilot state')
    } catch (error) {
      const message = (error as Error)?.message ?? String(error)
      addAlert('error', 'Unable to update pilot style: ' + message)
    }
  }

  async function sendPilotChat() {
    const message = pilotInput.trim()
    if (!message) {
      addAlert('error', 'Message cannot be empty')
      return
    }
    pilotChatLoading = true
    const historyPayload = pilotChatHistory.map((entry) => ({ role: entry.role, content: entry.content }))
    pilotChatHistory = [...pilotChatHistory, { role: 'user', content: message }]
    pilotInput = ''
    try {
      const res = await apiFetch('/api/pilot/chat', {
        method: 'POST',
        body: JSON.stringify({ message, history: historyPayload }),
      })
      const replyText = res?.reply ?? '(no reply)'
      pilotChatHistory = [...pilotChatHistory, { role: 'assistant', content: replyText }]
    } catch (error) {
      const messageText = (error as Error)?.message ?? String(error)
      addAlert('error', 'Pilot chat failed: ' + messageText)
      pilotChatHistory = pilotChatHistory.slice(0, -1)
    } finally {
      pilotChatLoading = false
    }
  }

  function resetPilotConversation() {
    pilotChatHistory = []
    pilotInput = ''
  }
</script>

<div class="min-h-screen pb-16">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
    <header class={panelClass + ' flex flex-col gap-6'}>
      <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
        <div>
          <h1 class="text-3xl md:text-4xl font-semibold text-white/90 flex items-center gap-3">
            <span class="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-white/10 border border-white/10 shadow-lg">
              🤖
            </span>
            Pilot Control Deck
          </h1>
          <p class="text-sm md:text-base text-white/60 max-w-2xl mt-2">
            Secure web console for managing the Discord bot, owner sync tooling, tracking utilities, and Pilot Chat prompts.
          </p>
        </div>
        <div class="flex flex-wrap items-center gap-3">
          {#if session.authenticated}
            <div class="px-4 py-2 rounded-2xl border border-white/10 bg-white/5 backdrop-blur">
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
        <span class="px-3 py-1 rounded-full border border-white/10 bg-white/5 backdrop-blur-sm">
          Permissions: {session.permissions?.length ? session.permissions.join(', ') : 'none'}
        </span>
        {#if statusData?.presence?.status}
          <span class="px-3 py-1 rounded-full border border-white/10 bg-white/5 backdrop-blur-sm">
            Current Presence: {statusData.presence.status}
          </span>
        {/if}
        {#if statusData?.presence?.activity?.name}
          <span class="px-3 py-1 rounded-full border border-white/10 bg-white/5 backdrop-blur-sm">
            Activity: {statusData.presence.activity.type ?? 'custom'} • {statusData.presence.activity.name}
          </span>
        {/if}
      </div>
    </header>

    {#if alerts.length}
      <div class="space-y-2">
        {#each alerts as alert (alert.id)}
          <div
            class={'flex items-center justify-between gap-4 rounded-2xl border px-4 py-3 text-sm backdrop-blur-sm ' + alertClass(alert.type)}
          >
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
            <section class="grid gap-6 md:grid-cols-3">
              <div class={cardClass}>
                <h3 class="text-sm text-white/50 uppercase tracking-wide">Bot Identity</h3>
                <p class="mt-3 text-lg font-semibold text-white/90">{statusData?.bot?.name ?? 'Unknown'}</p>
                <p class="text-xs text-white/40 mt-1">ID: {statusData?.bot?.id ?? 'n/a'}</p>
                <p class="text-xs text-white/40 mt-1">Guilds: {statusData?.guild_count ?? '—'}</p>
              </div>

              <div class={cardClass}>
                <h3 class="text-sm text-white/50 uppercase tracking-wide">Presence</h3>
                <p class="mt-3 text-white/80 text-sm">
                  Status: {statusData?.presence?.status ?? 'unknown'}
                </p>
                {#if statusData?.presence?.activity?.name}
                  <p class="text-white/60 text-sm mt-1">
                    Activity: {statusData.presence.activity.type ?? 'custom'} → {statusData.presence.activity.name}
                  </p>
                {/if}
                <p class="text-white/40 text-xs mt-2">
                  Latency:
                  {#if statusData?.latency}
                    {(statusData.latency * 1000).toFixed(0)} ms
                  {:else}
                    n/a
                  {/if}
                </p>
              </div>

              <div class={cardClass}>
                <h3 class="text-sm text-white/50 uppercase tracking-wide">Sync</h3>
                <p class="mt-3 text-white/80 text-sm">
                  Mode: {syncData?.enabled ? 'following owner' : 'manual'}
                </p>
                {#if syncData?.stored_activity}
                  <p class="text-white/60 text-sm mt-1">
                    Stored: {syncData.stored_activity.type ?? 'custom'} → {syncData.stored_activity.name}
                  </p>
                {/if}
                {#if syncData?.owner_status}
                  <p class="text-xs text-white/40 mt-2">Owner status: {syncData.owner_status}</p>
                {/if}
              </div>
            </section>
          {/if}
          {#if activeTab === 'presence'}
            <section class="space-y-6">
              {#if hasPerm('set_status')}
                <div class={cardClass}>
                  <h3 class="text-lg font-semibold text-white/90">Update Activity</h3>
                  <p class="text-sm text-white/50 mb-4">Mirrors the <code>/setstatus</code> command.</p>
                  <form class="space-y-4" on:submit|preventDefault={submitStatus}>
                    <div class="grid gap-4 md:grid-cols-2">
                      <label class="flex flex-col gap-2 text-sm text-white/70">
                        Activity Type
                        <select
                          class="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white/90"
                          bind:value={statusForm.type}
                        >
                          {#each statusTypes as option}
                            <option value={option.value}>{option.label}</option>
                          {/each}
                        </select>
                      </label>
                      <label class="flex flex-col gap-2 text-sm text-white/70">
                        Status Text
                        <input
                          class="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white"
                          placeholder="i hate dusekkar"
                          bind:value={statusForm.text}
                        />
                      </label>
                    </div>
                    <button
                      class="px-4 py-2 rounded-xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition"
                      type="submit"
                    >
                      Apply Activity
                    </button>
                  </form>
                </div>
              {/if}

              {#if hasPerm('set_online_status')}
                <div class={cardClass}>
                  <h3 class="text-lg font-semibold text-white/90">Presence State</h3>
                  <p class="text-sm text-white/50 mb-4">Matches the <code>/setonline</code> command.</p>
                  <div class="flex flex-col md:flex-row gap-4 md:items-end">
                    <label class="flex flex-col gap-2 text-sm text-white/70 w-full md:w-auto">
                      Choose State
                      <select
                        class="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white/90"
                        bind:value={onlineStatus}
                      >
                        {#each onlineStatusOptions as option}
                          <option value={option.value}>{option.label}</option>
                        {/each}
                      </select>
                    </label>
                    <button
                      class="px-4 py-2 rounded-xl border border-accent2/40 bg-accent2/20 text-accent2 hover:bg-accent2/30 transition"
                      on:click={submitOnlineStatus}
                    >
                      Update Presence
                    </button>
                  </div>
                </div>
              {/if}

              {#if hasPerm('clear_status')}
                <div class={cardClass}>
                  <h3 class="text-lg font-semibold text-white/90">Clear Activity</h3>
                  <p class="text-sm text-white/50 mb-4">Equivalent to <code>/clearstatus</code>.</p>
                  <button
                    class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition"
                    on:click={clearStatus}
                  >
                    Clear Current Activity
                  </button>
                </div>
              {/if}

              {#if hasPerm('update_bio')}
                <div class={cardClass}>
                  <h3 class="text-lg font-semibold text-white/90">Update Bot Bio</h3>
                  <p class="text-sm text-white/50 mb-4">Mirrors <code>/updatebio</code>.</p>
                  <div class="space-y-3">
                    <textarea
                      class="w-full min-h-[120px] bg-white/5 border border-white/10 rounded-2xl px-4 py-3 text-white"
                      placeholder="Giorgio's favorite co-pilot"
                      bind:value={bioText}
                    ></textarea>
                    <button
                      class="px-4 py-2 rounded-xl border border-accentWarn/40 bg-accentWarn/20 text-accentWarn hover:bg-accentWarn/30 transition"
                      on:click={updateBio}
                    >
                      Update Bio
                    </button>
                  </div>
                </div>
              {/if}

              {#if hasPerm('send_message')}
                <div class={cardClass}>
                  <h3 class="text-lg font-semibold text-white/90">Send Discord Message</h3>
                  <p class="text-sm text-white/50 mb-4">Utility endpoint for quick announcements.</p>
                  <div class="space-y-3">
                    <div class="grid gap-3 md:grid-cols-[1fr_2fr]">
                      <input
                        class="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white"
                        placeholder="Channel ID"
                        bind:value={messageForm.channelId}
                      />
                      <input
                        class="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white"
                        placeholder="Message content"
                        bind:value={messageForm.content}
                      />
                    </div>
                    <button
                      class="px-4 py-2 rounded-xl border border-white/20 bg-white/10 text-white/80 hover:text-white transition"
                      on:click={sendDiscordMessage}
                    >
                      Send Message
                    </button>
                  </div>
                </div>
              {/if}
            </section>
          {/if}
          {#if activeTab === 'sync'}
            <section class="space-y-6">
              <div class={cardClass}>
                <h3 class="text-lg font-semibold text-white/90">Owner Sync</h3>
                <p class="text-sm text-white/50 mb-4">Controls the sync enable/disable commands.</p>
                <div class="grid gap-4 md:grid-cols-2">
                  <div>
                    <p class="text-white/70 text-sm">Current mode</p>
                    <p class="text-xl text-white/90 font-semibold">
                      {syncData?.enabled ? 'Following owner' : 'Manual control'}
                    </p>
                    {#if syncData?.manually_set_offline}
                      <p class="text-xs text-rose-300 mt-1">Bot was manually set to Invisible.</p>
                    {/if}
                  </div>
                  <div class="space-x-2">
                    {#if hasPerm('sync_manage')}
                      <button
                        class="px-4 py-2 rounded-xl border border-emerald-400/40 bg-emerald-400/10 text-emerald-100 hover:bg-emerald-400/20 transition"
                        on:click={() => enableSync(true)}
                      >
                        Enable Sync
                      </button>
                      <button
                        class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition"
                        on:click={() => enableSync(false)}
                      >
                        Disable Sync
                      </button>
                    {/if}
                  </div>
                </div>
              </div>
            </section>
          {/if}
          {#if activeTab === 'tracking'}
            <section class="space-y-6">
              <div class={cardClass}>
                <h3 class="text-lg font-semibold text-white/90">Tracked User</h3>
                <p class="text-sm text-white/50 mb-4">Web equivalents for the tracking commands.</p>
                <div class="grid gap-6 md:grid-cols-2">
                  <div class="space-y-3">
                    <div>
                      <p class="text-white/60 text-sm">Currently tracking</p>
                      <p class="text-xl text-white/90 font-semibold">
                        {trackingStatus?.tracked_user_id ? trackingStatus.tracked_user_id : 'No tracking target'}
                      </p>
                      {#if trackingStatus?.in_server !== undefined}
                        <p class={trackingStatus.in_server ? 'text-sm mt-1 text-emerald-300' : 'text-sm mt-1 text-white/40'}>
                          {trackingStatus.in_server ? '🟢 In server' : '🔴 Not in server'}
                        </p>
                      {/if}
                      {#if trackingStatus?.current_session?.duration_text}
                        <p class="text-xs text-white/40 mt-2">
                          Current session: {trackingStatus.current_session.duration_text}
                        </p>
                      {/if}
                    </div>
                    {#if hasPerm('tracking_manage')}
                      <div class="flex flex-col sm:flex-row gap-3">
                        <input
                          class="flex-1 bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white"
                          placeholder="Discord user ID"
                          bind:value={trackingUserInput}
                        />
                        <button
                          class="px-4 py-2 rounded-xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition"
                          on:click={setTrackingUserId}
                        >
                          Set Target
                        </button>
                      </div>
                      <button
                        class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition"
                        on:click={clearTrackingData}
                      >
                        Clear Tracking Data
                      </button>
                    {/if}
                  </div>
                  <div>
                    <h4 class="text-sm text-white/60 uppercase tracking-wide mb-2">Top Sessions</h4>
                    <div class="max-h-60 overflow-y-auto pr-2 space-y-2 text-sm">
                      {#if trackingLeaderboard?.length}
                        {#each trackingLeaderboard as entry, index}
                          <div class="flex items-center justify-between bg-white/5 border border-white/10 rounded-xl px-3 py-2">
                            <span class="text-white/70">#{index + 1}</span>
                            <span class="text-white/80 font-medium">{entry.duration}</span>
                            <span class="text-xs text-white/40">Joined {entry.join_time.split('T')[0]}</span>
                          </div>
                        {/each}
                      {:else}
                        <p class="text-white/40">No sessions recorded yet.</p>
                      {/if}
                    </div>
                  </div>
                </div>
              </div>
            </section>
          {/if}
          {#if activeTab === 'access'}
            <section class="space-y-6">
              <div class={cardClass}>
                <h3 class="text-lg font-semibold text-white/90">Access Control</h3>
                <p class="text-sm text-white/50 mb-4">
                  Grant dashboard access to Discord IDs and choose the scopes they can use. Admins automatically inherit every permission.
                </p>

                {#if permissionsData.length === 0}
                  <p class="text-white/50 text-sm border border-dashed border-white/10 rounded-2xl p-4">
                    No additional users have been granted access yet.
                  </p>
                {:else}
                  <div class="space-y-4">
                    {#each permissionsData as entry (entry.id)}
                      <div class="border border-white/10 rounded-2xl p-5 bg-white/5">
                        <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                          <div>
                            <p class="text-white/80 font-semibold text-sm">Discord ID</p>
                            <p class="text-white/90 text-base font-medium">{entry.id}</p>
                            <p class="text-xs text-white/40 mt-1">
                              Current: {permissionsDraft[entry.id]?.length ? permissionsDraft[entry.id].join(', ') : 'No permissions'}
                            </p>
                          </div>
                          <div class="flex gap-2 flex-wrap">
                            <button
                              class="px-4 py-2 rounded-xl border border-emerald-400/40 bg-emerald-400/10 text-emerald-100 hover:bg-emerald-400/20 transition"
                              on:click={() => saveExistingPermissions(entry.id)}
                            >
                              Save Changes
                            </button>
                            <button
                              class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition"
                              on:click={() => removePermissionsUser(entry.id)}
                            >
                              Remove Access
                            </button>
                          </div>
                        </div>
                        <div class="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                          {#each availablePermissions as perm}
                            <label class="flex items-center gap-2 text-sm text-white/70 bg-white/5 border border-white/10 rounded-xl px-3 py-2">
                              <input
                                type="checkbox"
                                class="accent-accent"
                                checked={permissionsDraft[entry.id]?.includes(perm)}
                                on:change={(event) => toggleExistingPermission(entry.id, perm, (event.currentTarget as HTMLInputElement).checked)}
                              />
                              <span>{perm}</span>
                            </label>
                          {/each}
                        </div>
                      </div>
                    {/each}
                  </div>
                {/if}

                <div class="mt-8 pt-6 border-t border-white/10">
                  <h4 class="text-white/80 font-semibold">Grant Access</h4>
                  <p class="text-xs text-white/40 mb-4">Enter a Discord user ID and choose at least one scope to grant dashboard access.</p>
                  <div class="flex flex-col sm:flex-row gap-3">
                    <input
                      class="flex-1 bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white"
                      placeholder="Discord user ID"
                      bind:value={newUserId}
                    />
                    <button
                      class="px-4 py-2 rounded-xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition"
                      on:click={addPermissionsUser}
                    >
                      Add / Update User
                    </button>
                  </div>
                  <div class="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                    {#each availablePermissions as perm}
                      <label class="flex items-center gap-2 text-sm text-white/70 bg-white/5 border border-white/10 rounded-xl px-3 py-2">
                        <input
                          type="checkbox"
                          class="accent-accent"
                          checked={newUserPerms.includes(perm)}
                          on:change={(event) => toggleNewUserPermission(perm, (event.currentTarget as HTMLInputElement).checked)}
                        />
                        <span>{perm}</span>
                      </label>
                    {/each}
                  </div>
                </div>
              </div>
            </section>
          {/if}
          {#if activeTab === 'pilot'}
            <section class="space-y-6">
              <div class={cardClass}>
                <h3 class="text-lg font-semibold text-white/90">Pilot Configuration</h3>
                <p class="text-sm text-white/50 mb-4">Manage Pilot mode and style.</p>
                {#if pilotState?.available}
                  <div class="grid gap-4 md:grid-cols-2">
                    <div>
                      <p class="text-white/70 text-sm">Status</p>
                      <p class="text-xl text-white/90 font-semibold">
                        {pilotState.enabled ? 'Enabled' : 'Disabled'}
                      </p>
                      <p class="text-white/50 text-sm mt-1">Style: {pilotState.style_mode ?? 'default'}</p>
                      <p class="text-white/40 text-xs mt-2">History limit: {pilotState.history_limit ?? 'n/a'}</p>
                    </div>
                    {#if hasPerm('pilot_manage')}
                      <div class="space-y-3">
                        <div class="flex gap-2 flex-wrap">
                          <button
                            class="px-4 py-2 rounded-xl border border-emerald-400/40 bg-emerald-400/10 text-emerald-100 hover:bg-emerald-400/20 transition"
                            on:click={() => togglePilotMode(true)}
                          >
                            Enable Pilot
                          </button>
                          <button
                            class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition"
                            on:click={() => togglePilotMode(false)}
                          >
                            Disable Pilot
                          </button>
                        </div>
                        <div class="flex gap-3 flex-wrap items-center">
                          <select
                            class="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white"
                            bind:value={pilotStyleInput}
                          >
                            {#each pilotStyleOptions as option}
                              <option value={option.value}>{option.label}</option>
                            {/each}
                          </select>
                          <button
                            class="px-4 py-2 rounded-xl border border-accent2/40 bg-accent2/20 text-accent2 hover:bg-accent2/30 transition"
                            on:click={updatePilotStyle}
                          >
                            Apply Style
                          </button>
                        </div>
                      </div>
                    {/if}
                  </div>
                {:else}
                  <p class="text-white/50">Pilot Chat cog is not loaded.</p>
                {/if}
              </div>
            </section>
          {/if}
          {#if activeTab === 'pilot-chat'}
            <section class="space-y-6">
              <div class={cardClass}>
                <div class="flex items-center justify-between">
                  <div>
                    <h3 class="text-lg font-semibold text-white/90">Pilot Chat Console</h3>
                    <p class="text-sm text-white/50">Call the same LLM broker Pilot uses in Discord.</p>
                  </div>
                  <button
                    class="px-4 py-2 rounded-xl border border-white/10 text-white/60 hover:text-white/90 transition"
                    on:click={resetPilotConversation}
                  >
                    Clear Conversation
                  </button>
                </div>

                {#if !pilotState?.enabled}
                  <div class="mt-4 p-4 rounded-2xl border border-amber-400/40 bg-amber-400/10 text-amber-100 text-sm">
                    Pilot mode is currently disabled. Enable it from the Pilot tab to chat.
                  </div>
                {/if}

                <div class="mt-6 space-y-4 max-h-[420px] overflow-y-auto pr-2">
                  {#if pilotChatHistory.length === 0}
                    <p class="text-white/40 text-sm">No messages yet. Say hello to Pilot.</p>
                  {:else}
                    {#each pilotChatHistory as entry}
                      <div
                        class={entry.role === 'user'
                          ? 'rounded-2xl px-4 py-3 max-w-xl bg-accent/20 border border-accent/40 ml-auto text-white'
                          : 'rounded-2xl px-4 py-3 max-w-xl bg-white/5 border border-white/10 text-white/80'}
                      >
                        <p class="text-xs uppercase tracking-wide text-white/50 mb-1">
                          {entry.role === 'user' ? 'You' : 'Pilot'}
                        </p>
                        <p class="whitespace-pre-wrap text-sm leading-relaxed">{entry.content}</p>
                      </div>
                    {/each}
                  {/if}
                </div>

                <div class="mt-6 space-y-3">
                  <textarea
                    class="w-full min-h-[120px] bg-white/5 border border-white/10 rounded-2xl px-4 py-3 text-white"
                    placeholder={pilotState?.enabled ? 'Type a message for Pilot…' : 'Pilot must be enabled to chat.'}
                    bind:value={pilotInput}
                    disabled={!pilotState?.enabled || pilotChatLoading}
                  ></textarea>
                  <button
                    class="px-5 py-3 rounded-2xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition disabled:opacity-40 disabled:cursor-not-allowed"
                    on:click={sendPilotChat}
                    disabled={!pilotState?.enabled || pilotChatLoading}
                  >
                    {pilotChatLoading ? 'Summoning Pilot…' : 'Send to Pilot'}
                  </button>
                </div>
              </div>
            </section>
          {/if}
        </div>
      </div>
    {/if}
  </div>
</div>
