/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sentinel: {
          primary: '#3b82f6',
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          info: '#22c55e',
          bg: {
            dark: '#0f172a',
            card: '#1e293b',
            elevated: '#334155',
          },
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
};
