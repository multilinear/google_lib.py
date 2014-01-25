This is a small library for interacting with google calendar and google drive.
It was written for my own webserver project (a signup system). So there are a few idiosyncracies and hardcoded bits, but it may still be useful as a starting point - particularly due to the difficulties of using oauth etc.

This library also includes abstractions for calendar events, and permissions. This may seem excessive, but it unifies calendar and drive's concepts of permissions (which differ slightly) and allows things like set operations making permissions handling easier. For events it's a simpler wrapper that's mostly there for pretty printing and the like.

Hopefully you'll find this useful. Note that google_lib.py can be run itself to initiate the oauth setup. Note additionally that it creates the "auth" directory one directory below itself - this is due to my own original usecase, if you don't like it change it :).
