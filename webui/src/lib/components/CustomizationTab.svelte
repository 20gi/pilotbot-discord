<script lang="ts">
  import type { ThemeSettings } from '../stores/theme'

  export let cardClass: string
  export let currentTheme: ThemeSettings
  export let defaultTheme: ThemeSettings
  export let saveTheme: (settings: ThemeSettings) => Promise<boolean>

  let draft: ThemeSettings = { ...currentTheme }
  let dirty = false
  let saving = false
  let useImage = Boolean(draft.background_image)

  $: if (!dirty) {
    draft = { ...currentTheme }
    useImage = Boolean(draft.background_image)
  }

  function markDirty() {
    dirty = true
  }

  function updateColor(key: keyof ThemeSettings, value: string) {
    draft = { ...draft, [key]: value }
    markDirty()
  }

  function updateBlur(key: 'background_blur' | 'panel_blur', value: string) {
    const numeric = Number(value)
    draft = { ...draft, [key]: Number.isFinite(numeric) ? Math.max(0, Math.min(64, Math.round(numeric))) : 0 }
    markDirty()
  }

  function setBackgroundMode(mode: 'color' | 'image') {
    useImage = mode === 'image'
    if (!useImage) {
      draft = { ...draft, background_image: '' }
    }
    markDirty()
  }

  function handleImageInput(value: string) {
    draft = { ...draft, background_image: value }
    markDirty()
  }

  function applyDefaults() {
    draft = { ...defaultTheme }
    useImage = Boolean(draft.background_image)
    dirty = true
  }

  function resetChanges() {
    draft = { ...currentTheme }
    useImage = Boolean(draft.background_image)
    dirty = false
  }

  async function handleSubmit() {
    if (saving || !dirty) return
    saving = true
    const payload: ThemeSettings = {
      ...draft,
      background_image: useImage ? (draft.background_image || '').trim() : '',
      background_blur: Number(draft.background_blur) || 0,
      panel_blur: Number(draft.panel_blur) || 0,
    }
    const ok = await saveTheme(payload)
    saving = false
    if (ok) {
      dirty = false
    }
  }
</script>

<section class={cardClass + ' space-y-6'}>
  <header class="space-y-1">
    <h2 class="text-xl font-semibold text-white/90">Global Theme</h2>
    <p class="text-sm text-white/50">Customize colors, backgrounds, and glass blur for everyone using the dashboard.</p>
  </header>

  <form class="space-y-6" on:submit|preventDefault={handleSubmit}>
    <div class="grid gap-4 md:grid-cols-2">
      <label class="flex flex-col gap-2">
        <span class="text-sm font-medium text-white/70">Background color</span>
        <input
          class="h-12 w-full rounded-xl border border-white/10 bg-white/5 px-3"
          type="color"
          value={draft.background_color}
          on:input={(event) => updateColor('background_color', (event.currentTarget as HTMLInputElement).value)}
        />
      </label>
      <label class="flex flex-col gap-2">
        <span class="text-sm font-medium text-white/70">Text color</span>
        <input
          class="h-12 w-full rounded-xl border border-white/10 bg-white/5 px-3"
          type="color"
          value={draft.text_color}
          on:input={(event) => updateColor('text_color', (event.currentTarget as HTMLInputElement).value)}
        />
      </label>
    </div>

    <div class="space-y-3">
      <span class="text-sm font-medium text-white/70">Background mode</span>
      <div class="flex flex-wrap items-center gap-4 text-sm text-white/70">
        <label class="inline-flex items-center gap-2">
          <input type="radio" name="bg-mode" value="color" checked={!useImage} on:change={() => setBackgroundMode('color')} />
          Solid color
        </label>
        <label class="inline-flex items-center gap-2">
          <input type="radio" name="bg-mode" value="image" checked={useImage} on:change={() => setBackgroundMode('image')} />
          Image URL
        </label>
      </div>
      {#if useImage}
        <input
          class="w-full rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white/80 placeholder:text-white/40 focus:border-accent/40 focus:outline-none"
          type="url"
          placeholder="https://example.com/wallpaper.jpg"
          value={draft.background_image}
          on:input={(event) => handleImageInput((event.currentTarget as HTMLInputElement).value)}
        />
      {/if}
    </div>

    <div class="grid gap-4 md:grid-cols-2">
      <label class="flex flex-col gap-2">
        <span class="text-sm font-medium text-white/70">Primary accent</span>
        <input
          class="h-12 w-full rounded-xl border border-white/10 bg-white/5 px-3"
          type="color"
          value={draft.accent_color}
          on:input={(event) => updateColor('accent_color', (event.currentTarget as HTMLInputElement).value)}
        />
      </label>
      <label class="flex flex-col gap-2">
        <span class="text-sm font-medium text-white/70">Secondary accent</span>
        <input
          class="h-12 w-full rounded-xl border border-white/10 bg-white/5 px-3"
          type="color"
          value={draft.accent_secondary_color}
          on:input={(event) => updateColor('accent_secondary_color', (event.currentTarget as HTMLInputElement).value)}
        />
      </label>
      <label class="flex flex-col gap-2">
        <span class="text-sm font-medium text-white/70">Warning accent</span>
        <input
          class="h-12 w-full rounded-xl border border-white/10 bg-white/5 px-3"
          type="color"
          value={draft.accent_warning_color}
          on:input={(event) => updateColor('accent_warning_color', (event.currentTarget as HTMLInputElement).value)}
        />
      </label>
      <label class="flex flex-col gap-2">
        <span class="text-sm font-medium text-white/70">Danger accent</span>
        <input
          class="h-12 w-full rounded-xl border border-white/10 bg-white/5 px-3"
          type="color"
          value={draft.accent_danger_color}
          on:input={(event) => updateColor('accent_danger_color', (event.currentTarget as HTMLInputElement).value)}
        />
      </label>
    </div>

    <div class="grid gap-6 md:grid-cols-2">
      <label class="flex flex-col gap-3">
        <div class="flex items-center justify-between text-sm text-white/70">
          <span>Background blur</span>
          <span class="text-white/50">{draft.background_blur}px</span>
        </div>
        <input
          type="range"
          min="0"
          max="64"
          step="1"
          value={draft.background_blur}
          on:input={(event) => updateBlur('background_blur', (event.currentTarget as HTMLInputElement).value)}
        />
      </label>
      <label class="flex flex-col gap-3">
        <div class="flex items-center justify-between text-sm text-white/70">
          <span>Panel blur</span>
          <span class="text-white/50">{draft.panel_blur}px</span>
        </div>
        <input
          type="range"
          min="0"
          max="64"
          step="1"
          value={draft.panel_blur}
          on:input={(event) => updateBlur('panel_blur', (event.currentTarget as HTMLInputElement).value)}
        />
      </label>
    </div>

    <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
      <div class="flex flex-wrap gap-3">
        <button
          type="button"
          class="px-4 py-2 rounded-xl border border-white/10 text-white/70 hover:text-white hover:border-white/30 transition"
          on:click={resetChanges}
        >
          Reset to current
        </button>
        <button
          type="button"
          class="px-4 py-2 rounded-xl border border-white/10 text-white/70 hover:text-white hover:border-white/30 transition"
          on:click={applyDefaults}
        >
          Load defaults
        </button>
      </div>
      <button
        type="submit"
        class="inline-flex items-center justify-center px-5 py-3 rounded-2xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
        disabled={!dirty || saving}
      >
        {saving ? 'Saving…' : 'Save theme'}
      </button>
    </div>
  </form>
</section>
