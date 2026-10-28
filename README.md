# KC STORE

The storefront has two persistence modes:

- Open `index.html` directly to use the browser's IndexedDB database (`GroveStore`) for local accounts and purchase history. Data stays in that browser profile.
- Run `node server.mjs` and open `http://localhost:3001` to use the SQLite database at `data/store.sqlite`. This mode stores account records, hashed passwords, addresses, and user-linked orders on disk.

The storefront falls back to browser storage when the server is unavailable. Passwords are hashed; payment choices are recorded as demo selections only, and no card payment is processed.
