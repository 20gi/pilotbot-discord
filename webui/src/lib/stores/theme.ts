import { writable } from 'svelte/store'

export interface ThemeSettings {
  background_color: string
  background_image: string
  accent_color: string
  accent_secondary_color: string
  accent_warning_color: string
  accent_danger_color: string
  text_color: string
  panel_surface_color: string
  panel_surface_opacity: number
  panel_card_color: string
  panel_card_opacity: number
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
  panel_surface_color: '#0b0f1a',
  panel_surface_opacity: 0.78,
  panel_card_color: '#0e1624',
  panel_card_opacity: 0.6,
  background_blur: 18,
  panel_blur: 11,
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

function hexToRgb(color: string): [number, number, number] | null {
  const sanitized = color?.startsWith('#') ? color.slice(1) : color
  if (!sanitized || sanitized.length !== 6) {
    return null
  }
  const bigint = Number.parseInt(sanitized, 16)
  if (Number.isNaN(bigint)) {
    return null
  }
  const r = (bigint >> 16) & 255
  const g = (bigint >> 8) & 255
  const b = bigint & 255
  return [r, g, b]
}

function toRgba(color: string, opacity: number, fallback: string): string {
  const components = hexToRgb(color)
  if (!components) return fallback
  const alpha = clamp(opacity, 0, 1)
  const [r, g, b] = components
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

function clamp(value: number, min: number, max: number): number {
  if (Number.isNaN(value)) return min
  return Math.min(Math.max(value, min), max)
}

function adjustOpacity(base: number, delta: number): number {
  return clamp(base + delta, 0, 1)
}

function blendForChip(color: string, opacity: number, fallback: string): { bg: string; border: string } {
  const components = hexToRgb(color)
  if (!components) {
    return { bg: fallback, border: fallback }
  }
  const [r, g, b] = components
  const chipOpacity = clamp(opacity * 0.85, 0, 1)
  const borderOpacity = clamp(opacity + 0.15, 0, 1)
  return {
    bg: `rgba(${r}, ${g}, ${b}, ${chipOpacity})`,
    border: `rgba(${r}, ${g}, ${b}, ${borderOpacity})`,
  }
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
  const surfaceColor = toRgba(theme.panel_surface_color, theme.panel_surface_opacity, 'rgba(11, 15, 26, 0.78)')
  const surfaceBorder = toRgba(theme.panel_surface_color, adjustOpacity(theme.panel_surface_opacity, 0.12), 'rgba(15, 22, 35, 0.9)')
  root.style.setProperty('--app-panel-surface-color', surfaceColor)
  root.style.setProperty('--app-panel-surface-border-color', surfaceBorder)
  const cardColor = toRgba(theme.panel_card_color, theme.panel_card_opacity, 'rgba(14, 22, 36, 0.6)')
  const cardBorder = toRgba(theme.panel_card_color, adjustOpacity(theme.panel_card_opacity, 0.18), 'rgba(28, 39, 56, 0.68)')
  root.style.setProperty('--app-panel-card-color', cardColor)
  root.style.setProperty('--app-panel-card-border-color', cardBorder)
  const chipColors = blendForChip(theme.panel_card_color, theme.panel_card_opacity, 'rgba(28, 39, 56, 0.65)')
  root.style.setProperty('--app-chip-background-color', chipColors.bg)
  root.style.setProperty('--app-chip-border-color', chipColors.border)
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
