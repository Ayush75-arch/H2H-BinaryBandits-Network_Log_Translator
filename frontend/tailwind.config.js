/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
      colors: {
        soc: {
          bg:      '#0b1220',
          panel:   '#111827',
          border:  '#1f2937',
          header:  '#0f1623',
          sidebar: '#0e1724',
        },
      },
    }
  },
  plugins: []
}
