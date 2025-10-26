<script lang="ts">
  export let cardClass: string
  export let syncData: any
  export let hasPerm: (perm: string) => boolean
  export let enableSync: (toggle: boolean) => Promise<void>

  let toggling = false

  async function handleToggle(toggle: boolean) {
    if (toggling) return
    toggling = true
    try {
      await enableSync(toggle)
    } finally {
      toggling = false
    }
  }
</script>

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
            class="px-4 py-2 rounded-xl border border-emerald-400/40 bg-emerald-400/10 text-emerald-100 hover:bg-emerald-400/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
            on:click={() => handleToggle(true)}
            disabled={toggling}
          >
            Enable Sync
          </button>
          <button
            class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
            on:click={() => handleToggle(false)}
            disabled={toggling}
          >
            Disable Sync
          </button>
        {/if}
      </div>
    </div>
  </div>
</section>
