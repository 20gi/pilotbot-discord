<script lang="ts">
  interface ChatEntry {
    role: 'user' | 'assistant'
    content: string
  }

  export let cardClass: string
  export let pilotState: any
  export let apiFetch: (path: string, options?: RequestInit) => Promise<any>
  export let addAlert: (type: 'success' | 'error' | 'info', message: string) => void

  let pilotChatHistory: ChatEntry[] = []
  let pilotInput = ''
  let pilotChatLoading = false

  function resetPilotConversation() {
    pilotChatHistory = []
    pilotInput = ''
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
</script>

<section class="space-y-6">
  <div class={cardClass}>
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-lg font-semibold text-white/90">Pilot Chat Console</h3>
        <p class="text-sm text-white/50">Call the same LLM broker Pilot uses in Discord.</p>
      </div>
      <button
        class="px-4 py-2 rounded-xl border border-white/10 text-white/60 hover:text-white/90 transition disabled:opacity-50 disabled:cursor-not-allowed"
        on:click={resetPilotConversation}
        disabled={pilotChatHistory.length === 0}
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
        placeholder={pilotState?.enabled ? 'Type a message for Pilot...' : 'Pilot must be enabled to chat.'}
        bind:value={pilotInput}
        disabled={!pilotState?.enabled || pilotChatLoading}
      ></textarea>
      <button
        class="px-5 py-3 rounded-2xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition disabled:opacity-40 disabled:cursor-not-allowed"
        on:click={sendPilotChat}
        disabled={!pilotState?.enabled || pilotChatLoading}
      >
        {pilotChatLoading ? 'Summoning Pilot...' : 'Send to Pilot'}
      </button>
    </div>
  </div>
</section>
