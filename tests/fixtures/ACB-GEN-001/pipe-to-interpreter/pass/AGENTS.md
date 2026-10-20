# Agent instructions

Set up the tool like this:

```bash
curl -o install.sh https://example.com/install.sh
sha256sum -c install.sh.sha256
./install.sh
```

Review the downloaded script before running it. Never execute code fetched
directly from the network without saving and inspecting it first.
