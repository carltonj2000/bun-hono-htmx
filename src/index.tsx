import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import { logger } from "hono/logger";

import ClickMe from "./clickme";
import Layout from "./layout";

const app = new Hono();

if (process.env.NODE_ENV === "dev") app.use("*", logger());
app.use("/static/styles.css", serveStatic({ path: "./public/styles.css" }));
app.use(
  "/static/htmx.1.9.10.min.js",
  serveStatic({ path: "./public/htmx.1.9.10.min.js" })
);

app.get("/hello", (c) => {
  return c.text("Hello Hono!");
});

app.get("/", (c) => {
  return c.html(
    <Layout>
      <div class="card max-w-[960px] mx-auto mt-3">
        <h1>Demo Links</h1>
        <div style={"display:flex; flex-direction: column;"}>
          <a href="/clickme">Click Me</a>
          <a href="/infinite-scroll">Infinite Scroll</a>
        </div>
      </div>
    </Layout>
  );
});

app.get("/clickme", (c) =>
  c.html(
    <Layout>
      <ClickMe />
    </Layout>
  )
);

const SomeJsxComponent = () => {
  return (
    <div>
      <h1>hi</h1>
    </div>
  );
};

app.get("/infinite-scroll", (c) => {
  return c.html(
    <Layout>
      <SomeJsxComponent />
    </Layout>
  );
});

app.post("/clicked", (c) => {
  return c.html(<h2>Clicked!</h2>);
});

export default app;
