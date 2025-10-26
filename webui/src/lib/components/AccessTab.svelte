<script lang="ts">
  interface PermissionUser {
    id: string
    permissions: string[]
  }

  export let cardClass: string
  export let availablePermissions: string[]
  export let permissionsData: PermissionUser[]
  export let permissionsDraft: Record<string, string[]>
  export let toggleExistingPermission: (userId: string, perm: string, enabled: boolean) => void
  export let saveExistingPermissions: (userId: string) => Promise<void>
  export let removePermissionsUser: (userId: string) => Promise<void>
  export let addPermissionsUser: (userId: string, permissions: string[]) => Promise<boolean>
  export let normalizePermOrder: (perms: string[]) => string[]

  let newUserId = ''
  let newUserPerms: string[] = []
  let addingUser = false
  let savingUserId: string | null = null
  let removingUserId: string | null = null

  function toggleNewUserPermission(perm: string, enabled: boolean) {
    const next = newUserPerms.filter((value) => value !== perm)
    if (enabled) {
      next.push(perm)
    }
    newUserPerms = normalizePermOrder(next)
  }

  async function handleSave(userId: string) {
    if (savingUserId) return
    savingUserId = userId
    try {
      await saveExistingPermissions(userId)
    } finally {
      savingUserId = null
    }
  }

  async function handleRemove(userId: string) {
    if (removingUserId) return
    removingUserId = userId
    try {
      await removePermissionsUser(userId)
    } finally {
      removingUserId = null
    }
  }

  async function handleAddUser() {
    if (addingUser) return
    addingUser = true
    try {
      const ok = await addPermissionsUser(newUserId, newUserPerms)
      if (ok) {
        newUserId = ''
        newUserPerms = []
      }
    } finally {
      addingUser = false
    }
  }
</script>

<section class="space-y-6">
  <div class={cardClass}>
    <h3 class="text-lg font-semibold text-white/90">Access Control</h3>
    <p class="text-sm text-white/50 mb-4">
      Grant dashboard access to Discord IDs and choose the scopes they can use. Admins automatically inherit every
      permission.
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
                  class="px-4 py-2 rounded-xl border border-emerald-400/40 bg-emerald-400/10 text-emerald-100 hover:bg-emerald-400/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
                  on:click={() => handleSave(entry.id)}
                  disabled={savingUserId === entry.id}
                >
                  {savingUserId === entry.id ? 'Saving...' : 'Save Changes'}
                </button>
                <button
                  class="px-4 py-2 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
                  on:click={() => handleRemove(entry.id)}
                  disabled={removingUserId === entry.id}
                >
                  {removingUserId === entry.id ? 'Removing...' : 'Remove Access'}
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
                    on:change={(event) =>
                      toggleExistingPermission(entry.id, perm, (event.currentTarget as HTMLInputElement).checked)}
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
      <p class="text-xs text-white/40 mb-4">
        Enter a Discord user ID and choose at least one scope to grant dashboard access.
      </p>
      <div class="flex flex-col sm:flex-row gap-3">
        <input
          class="flex-1 bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white"
          placeholder="Discord user ID"
          bind:value={newUserId}
          disabled={addingUser}
        />
        <button
          class="px-4 py-2 rounded-xl border border-accent/40 bg-accent/20 text-accent hover:bg-accent/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
          on:click={handleAddUser}
          disabled={addingUser}
        >
          {addingUser ? 'Saving...' : 'Add / Update User'}
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
              disabled={addingUser}
            />
            <span>{perm}</span>
          </label>
        {/each}
      </div>
    </div>
  </div>
</section>
