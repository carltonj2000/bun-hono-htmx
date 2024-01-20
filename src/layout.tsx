const Layout = ({ children }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Bun, Hono &amp; Htmx</title>

        <link href="/static/styles.css" rel="stylesheet"></link>
        <script src="/static/htmx.1.9.10.min.js" />
      </head>
      <body>{children}</body>
    </html>
  );
};

export default Layout;
