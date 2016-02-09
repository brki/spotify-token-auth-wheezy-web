from spotifyauth import encryption

#ENCRYPTION_STYLE=encryption.QUICK_ENCRYPTION
ENCRYPTION_STYLE=encryption.SECURE_ENCRYPTION

SPOTIFY_ACCOUNTS_ENDPOINT="https://accounts.spotify.com"
SPOTIFY_TOKEN_ENDPOINT=SPOTIFY_ACCOUNTS_ENDPOINT + '/api/token'

# You probably want to set real values for these in s configlocal.py file:
ENCRYPTION_SALT=b"Some arbitrary length string here"
ENCRYPTION_KEY=b"some string that has a length of 32 bytes comes here"[:32]

SPOTIFY_CLIENT_ID=b"Your spotify client id"
SPOTIFY_CLIENT_SECRET=b"Your spotify client secret"
SPOTIFY_CALLBACK_URL="Your app's spotify callback URL for redirecting to after authentication completes"

# The URL path from which these will be served.
APP_REFRESH_PATH="refresh"  # For a url like https://tokenswap.example.org/refresh
APP_SWAP_PATH="swap"

try:
    from spotifyauth.configlocal import *
except:
    print("No spotifyauth.configlocal present, using nonsense values")
