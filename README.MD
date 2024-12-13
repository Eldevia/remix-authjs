# Auth.js for Remix

```bash
npm i remix-authjs
```

**eldevia/remix-authjs** is a seamless integration of **Auth.js** into **Remix**, making authentication implementation in your Remix applications straightforward and efficient. Forked from https://github.com/acoreyj/next-auth

## Features

- Compatible with Auth.js adapters and providers.
- Effortless setup.
- Supports a wide range of authentication providers.
- Fully integrates with Remix’s progressive enhancement features.

---

## Configuration

### Update `remix.config.js`

In your `remix.config.js`, ensure required dependencies are bundled for proper functionality. Include `@auth/core`, `oauth4webapi`, `preact-render-to-string`, and any providers you intend to use.

Example configuration:

```js
// remix.config.js
module.exports = {
  // Other configuration...
  serverDependenciesToBundle: [
    "@auth/core",
    "oauth4webapi",
    "preact-render-to-string",
    "@auth/core/providers/google", // Replace/add providers as needed
  ],
};
```

---

## Usage

### Step 1: Create an Authenticator Service

Define a `.server` file (e.g., `services/auth.server.ts`) to set up and access the authenticator instance.

```ts
import { RemixAuthenticator } from "remix-authjs";
import Google from "@auth/core/providers/google";
import type { AppLoadContext } from "@remix-run/cloudflare";
import PostgresAdapter from "@auth/pg-adapter";
import pg from "pg";
const { Pool } = pg;

const required = [
  'DB_HOST',
  'DB_USERNAME',
  'DB_PASSWORD',
  'DB_NAME',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET'
];

const missing = required.filter(key => !process.env[key]);

if (missing.length > 0) {
  throw new Error(
    `Missing required environment variables: ${missing.join(', ')}`
  );
}

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

let authenticator: RemixAuthenticator<Record<string, unknown>>;

export const getAuthenticator = (env: Record<string, any> | AppLoadContext) => {
  if (!authenticator) {
    authenticator = new RemixAuthenticator({
      session: {
        strategy: "jwt",
      },
      debug: env.NODE_ENV === "development",
      adapter: PostgresAdapter(pool),
      providers: [
        Google({
          clientId: env.GOOGLE_CLIENT_ID as string,
          clientSecret: env.GOOGLE_CLIENT_SECRET as string,
        }) as unknown as any,
      ],
    }, env, '/auth');
  }
  return authenticator;
};
```

---

### Step 2: Create Authentication Routes

Create a resource route (e.g., `auth.$action.($providerId).tsx`) for handling authentication actions.

> **Note**: This must be a **Resource Route** to ensure progressive enhancement and CSRF protection.

```ts
import type { ActionFunction, LoaderFunction } from "@remix-run/node";
import { getAuthenticator } from "~/services/auth.server";

export const loader: LoaderFunction = async ({ request, params, context }) => {
  const authenticator = getAuthenticator(context.env as Record<string, string>);
  return authenticator.handleAuthRoute({
    request,
    action: params.action!,
    providerId: params.providerId,
    params,
  });
};

export const action: ActionFunction = async ({ request, params, context }) => {
  const authenticator = getAuthenticator(context.env as Record<string, string>);
  return authenticator.handleAuthRoute({
    request,
    action: params.action!,
    providerId: params.providerId,
    params,
  });
};
```

---

### Step 3: Environment Variables

Set the following environment variables for proper functionality:

1. **`AUTH_SECRET`**: A 32-character random string for security. Generate it using:
   ```bash
   openssl rand -hex 32
   ```

2. **`AUTH_TRUST_HOST`**: Set to `true` for non-Vercel deployments (e.g., Cloudflare Pages, Netlify).

---

## Sign In, Sign Out, and User Data

Use Remix’s progressive enhancement capabilities to create authentication components that work even without JavaScript.

Example:

```ts
import { getAuthenticator } from "~/services/auth.server";
import type { LoaderFunctionArgs } from "@remix-run/cloudflare";
import { useRef } from "react";
import { useFetcher, useLoaderData } from "@remix-run/react";
import { SignInForm, SignOutForm } from "remix-authjs";

export const loader = async ({ request, context }: LoaderFunctionArgs) => {
  const authenticator = getAuthenticator(context.env as Record<string, any>);
  const providers = await authenticator.getProviders(request);
  const user = await authenticator.isAuthenticated(request);
  return { user, providers };
};

export default function AuthPage() {
  const { user, providers } = useLoaderData<typeof loader>();
  const fetcher = useFetcher();
  const loading = fetcher.state === "loading" || fetcher.state === "submitting";
  const signOutForm = useRef<HTMLFormElement>(null);

  return (
    <div>
      <section className="container">
        {user ? (
          <div>
            <h1>Welcome, {user.name}</h1>
            <SignOutForm ref={signOutForm} fetcher={fetcher}>
              <button disabled={loading} aria-busy={loading}>
                Sign Out
              </button>
            </SignOutForm>
          </div>
        ) : (
          <>
            {Object.entries(providers).map(([key, provider]) => (
              <SignInForm fetcher={fetcher} providerId={provider.id} key={key}>
                <input
                  type="hidden"
                  name="callbackUrl"
                  value={typeof window !== "undefined" ? window.location.href : ""}
                />
                {provider.type === "email" && (
                  <>
                    <label htmlFor="email">Email address</label>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      placeholder="Enter your email"
                      required
                    />
                  </>
                )}
                <button disabled={loading} aria-busy={loading}>
                  Sign In with {provider.name}
                </button>
              </SignInForm>
            ))}
          </>
        )}
      </section>
    </div>
  );
}
```

---

## Callback URL

Set the callback URL for providers to:

```
[origin]/auth/callback/[provider]
```

---

### Additional Notes

- **Email Authentication**: Customize the route or login page to handle email-based authentication responses (e.g., messages about email confirmation).
- **Resource Route Importance**: Ensure your routes follow Remix’s Resource Route standards for secure CSRF handling.

For more details, check out the [Remix documentation on Resource Routes](https://remix.run/docs/en/main/guides/resource-routes).

