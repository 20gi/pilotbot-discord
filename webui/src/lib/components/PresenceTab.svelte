<script lang="ts">
  interface StatusOption {
    value: string
    label: string
  }

  interface MessageForm {
    channelId: string
    content: string
  }

  export let cardClass: string
  export let statusTypes: StatusOption[]
  export let onlineStatusOptions: StatusOption[]
  export let hasPerm: (perm: string) => boolean
  export let submitStatus: (form: { type: string; text: string }) => Promise<boolean>
  export let submitOnlineStatus: (status: string) => Promise<boolean>
  export let clearStatus: () => Promise<boolean>
  export let updateBio: (bio: string) => Promise<boolean>
  export let sendDiscordMessage: (payload: MessageForm) => Promise<boolean>

  let statusForm = {
    type: statusTypes?.[0]?.value ?? 'playing',
    text: '',
  }
  let onlineStatus = onlineStatusOptions?.[0]?.value ?? 'online'
  let bioText = ''
  let messageForm: MessageForm = { channelId: '', content: '' }

  let statusSubmitting = false
  let onlineSubmitting = false
  let clearSubmitting = false
  let bioSubmitting = false
  let messageSubmitting = false

  async function handleSubmitStatus() {
    if (statusSubmitting) return
    statusSubmitting = true
    try {
      const ok = await submitStatus(statusForm)
      if (ok) {
        statusForm = { ...statusForm, text: '' }
      }
    } finally {
      statusSubmitting = false
    }
  }

  async function handleSubmitOnlineStatus() {
    if (onlineSubmitting) return
    onlineSubmitting = true
    try {
      await submitOnlineStatus(onlineStatus)
    } finally {
      onlineSubmitting = false
    }
  }

  async function handleClearStatus() {
    if (clearSubmitting) return
    clearSubmitting = true
    try {
      await clearStatus()
    } finally {
      clearSubmitting = false
    }
  }

  async function handleUpdateBio() {
    if (bioSubmitting) return
    bioSubmitting = true
    try {
      const ok = await updateBio(bioText)
      if (ok) {
        bioText = ''
      }
    } finally {
      bioSubmitting = false
    }
  }

  async function handleSendMessage() {
    if (messageSubmitting) return
    messageSubmitting = true
    try {
      const ok = await sendDiscordMessage(messageForm)
      if (ok) {
        messageForm = { channelId: '', content: '' }
      }
    } finally {
      messageSubmitting = false
    }
  }
</script>

<section class="space-y-6">
  {#if hasPerm('set_status')}
    <div class={cardClass}>
      <h3 class="text-lg font-semibold text-white/90">Update Activity</h3>
      <p class="text-sm text-white/50 mb-4">Mirrors the <code>/setstatus</code> command.</p>
      <form class="space-y-4" on:submit|preventDefault={handleSubmitStatus}>
        <div class="grid gap-4 md:grid-cols-2">
          <label class="flex flex-col gap-2 text-sm text-white/70">
            Activity Type
            <select
              class="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white/90"
              bind:value={statusForm.type}
              disabled={statusSubmitting}
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
              disabled={statusSubmitting}
            />
          </label>
        </div>
        <button
          class="px-4 py-2 rounded-xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
          type="submit"
          disabled={statusSubmitting}
        >
          {statusSubmitting ? 'Applying...' : 'Apply Activity'}
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
            disabled={onlineSubmitting}
          >
            {#each onlineStatusOptions as option}
              <option value={option.value}>{option.label}</option>
            {/each}
          </select>
        </label>
        <button
          class="px-4 py-2 rounded-xl border border-accent2/40 bg-accent2/20 text-accent2 hover:bg-accent2/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
          on:click={handleSubmitOnlineStatus}
          disabled={onlineSubmitting}
        >
          {onlineSubmitting ? 'Updating...' : 'Update Presence'}
        </button>
      </div>
    </div>
  {/if}

  {#if hasPerm('clear_status')}
    <div class={cardClass}>
      <h3 class="text-lg font-semibold text-white/90">Clear Activity</h3>
      <p class="text-sm text-white/50 mb-4">Equivalent to <code>/clearstatus</code>.</p>
      <button
        class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
        on:click={handleClearStatus}
        disabled={clearSubmitting}
      >
        {clearSubmitting ? 'Clearing...' : 'Clear Current Activity'}
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
          disabled={bioSubmitting}
        ></textarea>
        <button
          class="px-4 py-2 rounded-xl border border-accentWarn/40 bg-accentWarn/20 text-accentWarn hover:bg-accentWarn/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
          on:click={handleUpdateBio}
          disabled={bioSubmitting}
        >
          {bioSubmitting ? 'Updating...' : 'Update Bio'}
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
            disabled={messageSubmitting}
          />
          <input
            class="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white"
            placeholder="Message content"
            bind:value={messageForm.content}
            disabled={messageSubmitting}
          />
        </div>
        <button
          class="px-4 py-2 rounded-xl border border-white/20 bg-white/10 text-white/80 hover:text-white transition disabled:opacity-50 disabled:cursor-not-allowed"
          on:click={handleSendMessage}
          disabled={messageSubmitting}
        >
          {messageSubmitting ? 'Sending...' : 'Send Message'}
        </button>
      </div>
    </div>
  {/if}
</section>
