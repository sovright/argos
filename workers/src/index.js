export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.hostname = "argos-sovright.pages.dev";
    return fetch(new Request(url.toString(), request), { redirect: "follow" });
  },
};
