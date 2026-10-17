/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        apple: {
          bg: "#000000",
          bgSecondary: "#080808",
          surface: "#101010",
          surfaceSecondary: "#181818",
          surfaceElevated: "#202020",
          surfaceHover: "#252525",
          separator: "#2A2A2A",
          separatorStrong: "#3A3A3A",
          textPrimary: "#F5F5F7",
          textSecondary: "#A1A1A6",
          textTertiary: "#737378",
          fillPrimary: "#FFFFFF",
          fillSecondary: "#D6D6D6",
        },
        vyra: {
          bg: "#000000",
          sidebar: "#080808",
          surface: "#101010",
          raised: "#181818",
          hover: "#252525",
          border: "#2A2A2A",
          borderStrong: "#3A3A3A",
          text: "#F5F5F7",
          secondary: "#A1A1A6",
          muted: "#737378",
          green: "#F5F5F7",
          greenHover: "#FFFFFF",
          greenSubtle: "#181818",
          greenBorder: "#3A3A3A",
          focus: "#FFFFFF",
          surface2: "#181818",
          pass: "#F5F5F7",
          fail: "#F5F5F7",
          warn: "#A1A1A6",
          info: "#737378"
        }
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Text"', '"SF Pro Display"', '"Helvetica Neue"', 'Arial', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', '"SF Mono"', 'Menlo', 'Monaco', 'Consolas', 'monospace']
      },
      borderRadius: {
        'apple-sm': '8px',
        'apple-md': '12px',
        'apple-lg': '16px',
        'apple-xl': '20px',
      }
    },
  },
  plugins: [],
}
