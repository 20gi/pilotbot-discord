import { writable } from 'svelte/store'

export interface ThemeSettings {
  background_color: string
  background_image: string
  accent_color: string
  accent_secondary_color: string
  accent_warning_color: string
  accent_danger_color: string
  text_color: string
  background_blur: number
  panel_blur: number
}

export const defaultTheme: ThemeSettings = {
  background_color: '#05070f',
  background_image: '',
  accent_color: '#60a5fa',
  accent_secondary_color: '#a855f7',
  accent_warning_color: '#f97316',
  accent_danger_color: '#f87171',
  text_color: '#f1f5f9',
  background_blur: 18,
  panel_blur: 8,
}

const { subscribe, set, update } = writable<ThemeSettings>({ ...defaultTheme })

function hexToRgbString(color: string): string {
  const sanitized = color?.startsWith('#') ? color.slice(1) : color
  if (!sanitized || sanitized.length !== 6) {
    return '255 255 255'
  }
  const bigint = Number.parseInt(sanitized, 16)
  if (Number.isNaN(bigint)) {
    return '255 255 255'
  }
  const r = (bigint >> 16) & 255
  const g = (bigint >> 8) & 255
  const b = bigint & 255
  return `${r} ${g} ${b}`
}

function toCssUrl(source: string): string {
  if (!source) return 'none'
  const escaped = source.replace(/"/g, '\\"')
  return `url("${escaped}")`
}

function applyThemeVariables(theme: ThemeSettings) {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  root.style.setProperty('--app-background-color', theme.background_color)
  root.style.setProperty('--app-background-image', toCssUrl(theme.background_image))
  const textRgb = hexToRgbString(theme.text_color)
  root.style.setProperty('--app-text-color-rgb', textRgb)
  root.style.setProperty('--app-text-color', `rgb(${textRgb})`)
  const accentRgb = hexToRgbString(theme.accent_color)
  root.style.setProperty('--app-accent-color-rgb', accentRgb)
  root.style.setProperty('--app-accent-color', `rgb(${accentRgb})`)
  const accent2Rgb = hexToRgbString(theme.accent_secondary_color)
  root.style.setProperty('--app-accent-secondary-color-rgb', accent2Rgb)
  root.style.setProperty('--app-accent-secondary-color', `rgb(${accent2Rgb})`)
  const accentWarnRgb = hexToRgbString(theme.accent_warning_color)
  root.style.setProperty('--app-accent-warning-color-rgb', accentWarnRgb)
  root.style.setProperty('--app-accent-warning-color', `rgb(${accentWarnRgb})`)
  const accentDangerRgb = hexToRgbString(theme.accent_danger_color)
  root.style.setProperty('--app-accent-danger-color-rgb', accentDangerRgb)
  root.style.setProperty('--app-accent-danger-color', `rgb(${accentDangerRgb})`)
  root.style.setProperty('--app-background-blur', `${theme.background_blur}px`)
  root.style.setProperty('--app-panel-blur', `${theme.panel_blur}px`)
}

subscribe((value) => applyThemeVariables(value))

export const theme = { subscribe }

export function setThemeSettings(settings: ThemeSettings) {
  const merged = { ...defaultTheme, ...settings }
  set(merged)
}

export function updateThemeSettings(partial: Partial<ThemeSettings>) {
  update((current) => {
    const merged = { ...current, ...partial }
    applyThemeVariables(merged)
    return merged
  })
}

export function resetThemeSettings() {
  set({ ...defaultTheme })
}

export function getCurrentTheme(): ThemeSettings {
  let current = { ...defaultTheme }
  const unsubscribe = subscribe((value) => {
    current = value
  })
  unsubscribe()
  return current
}
