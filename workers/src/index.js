const COOKIE_NAME = "argos_access";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

const LOGIN_PAGE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Argos — Early Access</title>
  <style>
    body { margin: 0; font-family: Inter, "Helvetica Neue", Arial, sans-serif; background: #fbf8f1; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .box { width: 100%; max-width: 360px; padding: 40px 32px; border: 1px solid #d8d1c4; border-radius: 10px; background: #fffdf8; }
    img { display: block; margin: 0 auto 20px; }
    h1 { margin: 0 0 6px; font-family: Georgia, serif; font-size: 1.6rem; text-align: center; }
    p { margin: 0 0 24px; color: #5d685f; font-size: 0.9rem; text-align: center; }
    input { width: 100%; box-sizing: border-box; padding: 11px 14px; border: 1px solid #d8d1c4; border-radius: 6px; font-size: 1rem; background: #fbf8f1; }
    button { margin-top: 12px; width: 100%; padding: 12px; border: none; border-radius: 6px; background: #1f6b56; color: #fff; font-size: 1rem; font-weight: 800; cursor: pointer; }
    button:hover { background: #143d34; }
    .error { margin-top: 12px; color: #b84040; font-size: 0.88rem; text-align: center; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Argos</h1>
    <p>Early access — enter the password to continue.</p>
    <form method="POST">
      <input type="password" name="password" placeholder="Password" autofocus />
      <button type="submit">Enter</button>
      {{ERROR}}
    </form>
  </div>
</body>
</html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "POST") {
      const body = await request.formData();
      if (body.get("password") === env.SITE_PASSWORD) {
        const dest = url.origin + "/";
        return new Response(null, {
          status: 302,
          headers: {
            Location: dest,
            "Set-Cookie": `${COOKIE_NAME}=1; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
          },
        });
      }
      return new Response(
        LOGIN_PAGE.replace("{{ERROR}}", '<p class="error">Incorrect password.</p>'),
        { status: 401, headers: { "Content-Type": "text/html" } }
      );
    }

    const cookie = request.headers.get("Cookie") || "";
    if (!cookie.includes(`${COOKIE_NAME}=1`)) {
      return new Response(LOGIN_PAGE.replace("{{ERROR}}", ""), {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    }

    url.hostname = "argos-sovright.pages.dev";
    return fetch(new Request(url.toString(), request), { redirect: "follow" });
  },
};
