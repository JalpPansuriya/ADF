/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Semantic names so status colours stay consistent across screens:
        // a revoked node and a denied audit row must read the same.
        allow: '#16a34a',
        deny: '#dc2626',
        pending: '#d97706',
        revoked: '#6b7280',
      },
    },
  },
  plugins: [],
};
