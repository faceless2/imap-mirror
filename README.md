# IMAP Mirror

A Java package to mirror an IMAP folder locally. Supports OAUTH2, so works with GMail, and has no dependencies

## Usage
```
ant
mkdir -p output/gmail
cp config-example.yaml config.yal
vi config.yaml      # edit the configuration,
java -jar dist/imap-mirror-all-0.1.jar --config config.yaml

Starting at NNN
[gmail] "INBOX": index was 2270 messages, added 0 in 132ms, now 2270
[gmail] "INBOX": ####****...........................................  (2270 existing, 0 new of 2270)
```

The configuration file specifies whichlooks like this:
```yaml
accounts:
  gmail:
    directory: /Users/user/output/gmail   # Where to store the mail. Required
    auth_password: "password"             # If authorization data is to be saved encrypted, a password to access it
    type: gmail
    email: test@test.com
    # Next three are the minimum required to access gmail accounts
    redirect_uri: http://127.0.0.1:5678/oauth
    client_id: xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com
    client_secret: xxxxxxxxxxxxxxxxxxxxxxxx

  generic:
    directory: /Users/user/output/generic
    email: test@test.com
    server: imap.test.com
    tls: true
    port: 1443
    password: "secret"
```

Authorization with the server is made, the messages are indexed and any that are not downloaded
yet will be downloaded. Messages are keyed on Message-ID, so if a message is stored in more than
one folder (as in GMail) then it will only be stored once, with hard-links to the same file in each 
folder.

Downloads can be interrupted and will be picked up where they left off.

OAUTH2 authorization data is stored in an `.authority` file in the directory for each account, and may be encrypted.
The message index for each folder is stored in an `.imap` file in each folder's directory; if it's deleted the
index will need to be be downloaded again, but messages themselves will never be downloaded more than once.
