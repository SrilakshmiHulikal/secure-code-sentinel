/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        sentinel: {
          50:  "#f0f4ff",
          100: "#dce7ff",
          200: "#b9cfff",
          300: "#7fabff",
          400: "#4d84ff",
          500: "#2563eb",
          600: "#1d4ed8",
          700: "#1e40af",
          800: "#1e3a8a",
          900: "#1e3370",
        },
      },
    },
  },
  plugins: [],
};
