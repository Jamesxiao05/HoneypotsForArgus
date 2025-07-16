# Honeypot Tracking Site used to track spoofing bots.

## Goals

Our objective is to create hidden link honeypots that are hidden throughout a realistic site that scraper bots can find. These honeypots are used to lure in these bots so that we can track information about their IP address, User Agent, Ports, and Headers. We use this information and a developed algorithm that is hosted publicly online so that we can analyze real time spoofers to obtain ground truth spoofers so that our AI models can utilize them as labels to understand and track how spoofers act and their patterns.

## Project Structure

1. Templates: Include all of the pages of the website to make it more realistic. All in HTML format.
2. Static: Includes the CSS file to make the site more stylish and the images to load on the site.
3. github/workflow: Used to auto-deploy to the server every time the repository is updated.

## Credentials

1. Supabase Link: `SUPABASE_URL` The URL to the supabase tables and logs
2. Supabase Key:  `SUPABASE_KEY` The key to access and have the logs be logged in the table

These credentials should be in a .env environment file.

## Build

This is the instructions on how to build the project.

### Prerequisites

- python3.11
- gunicorn (optional)

1. Clone the github repository
2. Create a virtual environment using the terminal `python3.11 -m venv venv`
3. After activating the virtual environment using `source venv/bin/activate`
4. Install poetry `pip install poetry`
5. Install the required packages using poetry `poetry install`. Note: ignore the error about running the code.

## Running the Server

The server can be deployed directly on port 8080 using: `poetry run python main.py`.

However, it is recommended to use a WSGI like `gunicorn` to manage paralallism to make the server more efficient to not overload the server.
