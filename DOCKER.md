# Running with Docker

## First time setup

1. Copy the example env file:
   ```
   cp .env.example .env
   ```

2. Add your Groq API key to `.env`:
   ```
   GROQ_API_KEY=your_key_here
   ```
   Get a free key at: https://console.groq.com

3. Build and run:
   ```
   docker compose up --build
   ```

## Run in demo mode (no API key needed)

```
DEMO_MODE=true docker compose up --build
```

## Analyze a .eml file

Put your `.eml` file inside the `samples/` folder, then run the container.
When prompted, enter the path as:

```
/app/samples/your-email.eml
```

## Stop the container

```
docker compose down
```
