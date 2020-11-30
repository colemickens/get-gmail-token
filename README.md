# get-xoauth2-token (gxt)

This tool gets an xoauth2 token and prints to stdin for a given login.

It's meant to be used with something like [`meli`](https://meli.delivery).
(You'll want the `use_oauth2` option and the `server_password_command` options.)

# usage

```shell
❯ ./get-xoauth2-token \
  --client-secret-path '~/client.json'\
  --username "cole.mickens@gmail.com"
You have not authenticated. You need to run this:

  ./get-xoauth2-token --client-secret-path '~/client.json' --username "cole.mickens@gmail.com" --login


❯ ./get-xoauth2-token \
  --client-secret-path '~/client.json'\
  --username "cole.mickens@gmail.com" \
  --login
Please direct your browser to https://accounts.google.com/o/oauth2/auth?scope=https://mail.google.com&access_type=offline&redirect_uri=http://127.0.0.1:41099&response_type=code&client_id=885945199677-vuo8qdimgva38orlljiosa8n6om0sksg.apps.googleusercontent.com and follow the instructions displayed there.
dXNlcj10ZXN0LmdjYWwuYXBpQGdtRedactedMFlwSE5rNlY4AQE=%

❯ ./get-xoauth2-token \
  --client-secret-path '~/client.json'\
  --username "cole.mickens@gmail.com"
dXNlcj10ZXN0LmdjYWwuYXBpQGdtRedactedMFlwSE5rNlY4AQE=%

# now meli can run the command without issue
# and it will just use the refresh_token as needed
```
