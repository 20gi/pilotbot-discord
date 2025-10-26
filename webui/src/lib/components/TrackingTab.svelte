<script lang="ts">
  interface LeaderboardEntry {
    duration: string
    join_time: string
  }

  export let cardClass: string
  export let trackingStatus: any
  export let trackingLeaderboard: LeaderboardEntry[]
  export let hasPerm: (perm: string) => boolean
  export let setTrackingUserId: (userId: string) => Promise<boolean>
  export let clearTrackingData: () => Promise<boolean>

  let trackingUserInput = ''
  let settingTracking = false
  let clearingTracking = false

  async function handleSetTracking() {
    if (settingTracking) return
    settingTracking = true
    try {
      const ok = await setTrackingUserId(trackingUserInput)
      if (ok) {
        trackingUserInput = ''
      }
    } finally {
      settingTracking = false
    }
  }

  async function handleClearTracking() {
    if (clearingTracking) return
    clearingTracking = true
    try {
      await clearTrackingData()
    } finally {
      clearingTracking = false
    }
  }
</script>

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
              {trackingStatus.in_server ? 'In server' : 'Not in server'}
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
              disabled={settingTracking}
            />
            <button
              class="px-4 py-2 rounded-xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
              on:click={handleSetTracking}
              disabled={settingTracking}
            >
              {settingTracking ? 'Setting...' : 'Set Target'}
            </button>
          </div>
          <button
            class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
            on:click={handleClearTracking}
            disabled={clearingTracking}
          >
            {clearingTracking ? 'Clearing...' : 'Clear Tracking Data'}
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
