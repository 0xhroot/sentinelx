/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sx: {
          bg: '#050505',
          'bg-alt': '#070707',
          surface: '#090909',
          card: '#0E0E0E',
          'card-hover': '#121212',
          border: 'rgba(255,255,255,0.06)',
          'border-hover': 'rgba(255,255,255,0.1)',
          'hover-bg': 'rgba(255,255,255,0.04)',
          muted: 'rgba(255,255,255,0.35)',
          subtle: 'rgba(255,255,255,0.55)',
          text: 'rgba(255,255,255,0.87)',
          white: '#FFFFFF',
          accent: '#3B82F6',
          'accent-hover': '#60A5FA',
          cyan: '#06B6D4',
          purple: '#8B5CF6',
          'purple-hover': '#A78BFA',
          green: '#22C55E',
          yellow: '#EAB308',
          orange: '#F97316',
          red: '#EF4444',
          'red-hover': '#F87171',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-out',
        'fade-in-up': 'fadeInUp 0.5s ease-out',
        'slide-in-right': 'slideInRight 0.3s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        fadeInUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideInRight: {
          '0%': { opacity: '0', transform: 'translateX(-10px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(59,130,246,0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(59,130,246,0.1)' },
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-card': 'linear-gradient(135deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0) 100%)',
      },
    },
  },
  plugins: [],
};
