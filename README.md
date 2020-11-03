Simply combines x/oauth2 and net/http/httputil's ReverseProxy to create
an in-band authentication tunnel.

## Local development ##

Navigate to https://github.com/settings/applications/new and set:

    application name: authtunnel
    homepage url: http://localhost:12345
    callback url: http://localhost:12345/login/callback

From this, get a client ID and secret for testing purposes.

Put those values into two environment variables:

    export OAUTH2_CLIENT_ID=""
    export OAUTH2_CLIENT_SECRET=""

Also, set `REDIRECT_URL` to whatever port / external URL you're using and the `/callback` path.

Then run `./authtunnel`.

