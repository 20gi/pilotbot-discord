<script lang="ts">
  interface PilotState {
    available?: boolean
    enabled?: boolean
    style_mode?: string
    history_limit?: number
  }

  interface StyleOption {
    value: string
    label: string
  }

  export let cardClass: string
  export let pilotState: PilotState
  export let pilotStyleOptions: StyleOption[]
  export let hasPerm: (perm: string) => boolean
  export let togglePilotMode: (desired: boolean) => Promise<void>
  export let updatePilotStyle: (mode: string) => Promise<boolean>

  let pilotStyleInput = pilotStyleOptions?.[0]?.value ?? 'default'
  let togglingPilot = false
  let savingStyle = false

  $: if (pilotState?.style_mode && !savingStyle) {
    pilotStyleInput = pilotState.style_mode
  }

  async function handleToggle(desired: boolean) {
    if (togglingPilot) return
    togglingPilot = true
    try {
      await togglePilotMode(desired)
    } finally {
      togglingPilot = false
    }
  }

  async function handleUpdateStyle() {
    if (savingStyle) return
    savingStyle = true
    try {
      await updatePilotStyle(pilotStyleInput)
    } finally {
      savingStyle = false
    }
  }
</script>

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
                class="px-4 py-2 rounded-xl border border-emerald-400/40 bg-emerald-400/10 text-emerald-100 hover:bg-emerald-400/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
                on:click={() => handleToggle(true)}
                disabled={togglingPilot}
              >
                {togglingPilot ? 'Updating...' : 'Enable Pilot'}
              </button>
              <button
                class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
                on:click={() => handleToggle(false)}
                disabled={togglingPilot}
              >
                {togglingPilot ? 'Updating...' : 'Disable Pilot'}
              </button>
            </div>
            <div class="flex gap-3 flex-wrap items-center">
              <select
                class="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white"
                bind:value={pilotStyleInput}
                disabled={savingStyle}
              >
                {#each pilotStyleOptions as option}
                  <option value={option.value}>{option.label}</option>
                {/each}
              </select>
              <button
                class="px-4 py-2 rounded-xl border border-accent2/40 bg-accent2/20 text-accent2 hover:bg-accent2/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
                on:click={handleUpdateStyle}
                disabled={savingStyle}
              >
                {savingStyle ? 'Saving...' : 'Apply Style'}
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
