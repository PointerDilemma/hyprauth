## hyprauth

Hyprauth is a parallel authentication library for cli and gui applications

## Brief

Hyprauth provides an interface for authenticating a user on linux and bsd systems.

Authenticating a specific user relies on an active login session for that user.
The library does not manage or create login sessions, it just verifies that the
input provider can authenticate on behalf of the user.

While PAM (Pluggable Authentication Modules) was designed to allow for different authentication methods,
it's API sadly doesn't support having multiple "providers" that are able to handle authentication input.
To support methods like fingerprint (also maybe facial recognition in the future) together with password authentication,
hyprauth offers a simple abstraction to allow authentication providers to run in parallel, with PAM being one of them.

The authentication provider interface may also be used to implement authentication protocols
that have side-effects like `greetd-ipc`.

## Implemented authentication providers

- Pam
- FprintDbus (using fprintd's dbus api)

## Dependencies

- hyprutils>=0.11.0
- hyprwire (For communicating with the pam client subprocess)
- sdbus-cpp>=2.0.0 (Required by the FprintDbus provider)
