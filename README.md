# TINET NETCHAT Server

As part of TINET, this server allows you to host your own
NETCHAT instance.  
> You would need to make an App API Key on TINET to get
authentication working.

> This system ensures that,
in case you abuse the authentication system, we can
ban the account the API key is being used on
and take action by banning this server instance from
TINET authentication.

## How to host a NETCHAT server
It is pretty simple, clone this repository
```shell
git clone -b master https://github.com/tkbstudios/netchatserver
cd netchatserver
```

1. run `python3 server.py` to set up files and directories.
2. edit the .env to include your [App API Key](https://tinet.tkbstudios.com/dashboard/app-api-keys)
instead of the changeme value (only if using online-mode, more on it later)
3. open server.properties and modify the settings as you'd like.
4. run `python3 server.py`  
want to use Docker? Run `sudo docker-compose up -d`

### Server settings
`host` is the IP address the server should listen on,
leave on 0.0.0.0 to listen on all interfaces.

`port` is the port the server should listen on,
leave on 2052 so clients don't need to enter the port
themselves, the client defaults to 2052 for TINET
hosted services.

`online-mode` is the setting that allows you to turn
TINET authentication on or off. It's NOT recommended
to turn it off, because people will be able to use
any username/session token they want, which might
result in server spam and impersonation.

`public-access-host` is the host that you give to your users that can be displayed to the user for them to connect to.

`enable-welcome-message` defines if you want to send a welcome message to the user. (`true` or `false`)

`welcome-message` is the message that gets displayed after the user connects to the server successfully.

`max-message-length` is the amount of characters a message can be 
(will likely be filtered by client but still useful in case you want shorter messages)

`announce-new-clients` will announce newly connected users to the global lobby. (`true` or `false`)

### Discord settings
`hook-enabled` defines if you want to bridge the message over to discord (can be `true` or `false`)

`hook-url` is the URL to the discord webhook
