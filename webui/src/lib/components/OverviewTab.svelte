<script lang="ts">
  export let cardClass: string
  export let statusData: any
  export let syncData: any
</script>

<section class="grid gap-6 md:grid-cols-3">
  <div class={cardClass}>
    <h3 class="text-sm text-white/50 uppercase tracking-wide">Bot Identity</h3>
    <p class="mt-3 text-lg font-semibold text-white/90">{statusData?.bot?.name ?? 'Unknown'}</p>
    <p class="text-xs text-white/40 mt-1">ID: {statusData?.bot?.id ?? 'n/a'}</p>
    <p class="text-xs text-white/40 mt-1">Guilds: {statusData?.guild_count ?? '-'}</p>
  </div>

  <div class={cardClass}>
    <h3 class="text-sm text-white/50 uppercase tracking-wide">Presence</h3>
    <p class="mt-3 text-white/80 text-sm">
      Status: {statusData?.presence?.status ?? 'unknown'}
    </p>
    {#if statusData?.presence?.activity?.name}
      <p class="text-white/60 text-sm mt-1">
        Activity: {statusData.presence.activity.type ?? 'custom'} &rarr; {statusData.presence.activity.name}
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
        Stored: {syncData.stored_activity.type ?? 'custom'} &rarr; {syncData.stored_activity.name}
      </p>
    {/if}
    {#if syncData?.owner_status}
      <p class="text-xs text-white/40 mt-2">Owner status: {syncData.owner_status}</p>
    {/if}
  </div>
</section>
