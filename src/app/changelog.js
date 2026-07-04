/* Mixin: the "What's new" changelog modal, shown from the header/landing page. */
export const changelogMixin = {
  openChangelogModal() {
    this.changelogModalOpen = true;
  },
  closeChangelogModal() {
    this.changelogModalOpen = false;
  }
};
