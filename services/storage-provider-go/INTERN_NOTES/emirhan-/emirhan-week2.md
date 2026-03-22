# Week 2 Progress
Here is what I did this week:

**1. Data Models (`types.go`)**
* Created Go "structs" to handle the JSON data we will receive from users (like IDs, Base64 strings, and Error messages).

**2. App Settings (`config.go`)**
* Wrote a function to read settings like the `PORT`, `SP_ID`, and `DATABASE_URL`. 
* Added default values (like port 8080) so the app can easily run on my local computer without extra setup.

**3. Helpers and the 8KB Limit (`helpers.go`)**
* Wrote helper functions to easily send and read JSON data.
* Added an important security rule: The server will reject any request bigger than 8KB to protect our memory.

**4. Middleware (The Checkpoints)**
I created 3 middleware functions that every request must pass through:
* **Request IDs:** Every incoming request gets a random ID so we can track it.
* **Logging:** The server prints out info about requests (like how long they took), but I made sure it **never logs secrets** like passwords or keys.
* **Panic Recovery:** If my code has a bug and crashes, this middleware catches the "panic" and returns a 500 error instead of shutting down the whole server.

**5. Routing (`routes.go`)**
* Set up all the URLs we planned for the project (like `/v1/setup` and `/v1/records`).
* I fully finished the `/v1/health` route. For the others, I added a "This feature is not implemented yet" message.

**6. Starting the Server (`main.go`)**
* Put everything together to start the server.
* Added "timeouts" (Read, Write, and Idle) so the server doesn't get stuck waiting for slow or fake connections.

**7. Testing (`health_test.go`)**
* Wrote an automated test using `httptest` for the `/v1/health` endpoint. 
* It automatically checks if the server returns `200 OK` and `{"ok":true}`.