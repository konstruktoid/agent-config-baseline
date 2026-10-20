# Agent instructions

```bash
docker run example/server:latest
docker run example/server:1.2
docker run -e X=y@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa evil/server:latest
docker run -v /x@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:/y evil/server:latest
nerdctl run evil/server:latest
kubectl run my-pod --image=evil/server:latest
FROM evil/server:latest
```

```json
{"image": "evil/server:latest"}
```
