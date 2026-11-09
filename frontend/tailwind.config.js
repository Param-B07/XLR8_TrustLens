/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0b1220",
        panel: "#111b2d",
        line: "#22314a",
        mint: "#55e6bd",
      },
    },
  },
  plugins: [],
};
