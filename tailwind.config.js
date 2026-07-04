/** @type {import('tailwindcss').Config} */
export default {
  // Scan the shell and every source template/module so utility classes used in
  // Alpine templates survive tree-shaking.
  content: ['./index.html', './src/**/*.{html,js}'],
  darkMode: 'class',
  theme: {
    extend: {
      // Element-type accent colours, shared with the graph legend. Previously
      // declared inline in index.html's CDN `tailwind.config` block.
      colors: {
        spackage: '#3b82f6',
        sfile: '#10b981',
        stool: '#f59e0b',
        sbuild: '#8b5cf6',
        sagent: '#ef4444',
        slicense: '#ec4899',
        sconfig: '#14b8a6'
      }
    }
  },
  plugins: []
};
