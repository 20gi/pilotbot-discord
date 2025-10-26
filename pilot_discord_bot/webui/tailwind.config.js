/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{svelte,js,ts}'],
  theme: {
    extend: {
      colors: {
        surface: '#0b0f1a',
        'surface-glass': 'rgba(17, 25, 40, 0.65)',
        accent: '#60a5fa',
        accent2: '#a855f7',
        accentWarn: '#f97316',
        accentDanger: '#f87171',
      },
      boxShadow: {
        glass: '0 20px 60px rgba(8, 15, 32, 0.35)',
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
}
