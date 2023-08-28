# falco-plugin-ig

## Compile and push the plugin

```
export CONTAINER_REPO=${USER}test.azurecr.io/falco-with-ig
export IMAGE_TAG=latest
PLATFORMS=linux/amd64 make container-build
```

## Run Falco with the plugin

```
docker pull $CONTAINER_REPO:$IMAGE_TAG
docker run --rm -i -t \
           --privileged \
           -v /var/run/docker.sock:/host/var/run/docker.sock \
           -v /sys/kernel/tracing:/sys/kernel/tracing \
           -v /proc:/host/proc:ro \
           $CONTAINER_REPO:$IMAGE_TAG falco --modern-bpf
```

You will see some events such as:
```
Critical Some event (ig.gadget=trace exec ig.comm=ssh)
```

## Limitations

- Events need to fit in 256KB (`sdk.DefaultEvtSize`) once encoded in json.
- 