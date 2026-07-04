const TAG_COLORS = {
  Added: 'bg-emerald-500/15 text-emerald-300',
  Improved: 'bg-sky-500/15 text-sky-300',
  Fixed: 'bg-amber-500/15 text-amber-300',
  Changed: 'bg-purple-500/15 text-purple-300'
};

/* Mixin: the "What's new" changelog modal, shown from the header/landing page. */
export const changelogMixin = {
  openChangelogModal() {
    this.changelogModalOpen = true;
  },
  closeChangelogModal() {
    this.changelogModalOpen = false;
  },
  changelogTagColor(tag) {
    return TAG_COLORS[tag] || 'bg-slate-600/30 text-slate-300';
  }
};
