# falco-plugin-ig

falco-plugin-ig is a Falco plugin that uses Inspektor Gadget
to run gadgets and feed events to Falco. It is a dynamic library
(libfalco-plugin-ig.so) loaded by the Falco process.

The following will explain two usages:
- Build a custom Falco container with the plugin and run it with Docker
- Publish the plugin as an OCI image with falcoctl and use it in Falco deployed on Kubernetes with Helm

## Custom Falco container with the plugin

### Build and push

```
export CONTAINER_REPO=${USER}test.azurecr.io/falco-with-ig
export IMAGE_TAG=latest
PLATFORMS=linux/amd64 make container-build
```

### Run Falco with the plugin

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

## On Kubernetes with the official Falco Helm chart

This uses the official Falco Helm chart: https://github.com/falcosecurity/charts

### Build and publish the Falco plugin OCI image

```
export OCI_FALCO_PLUGIN=${USER}test.azurecr.io/falco-plugin-ig
export OCI_FALCO_PLUGIN_VERSION=0.1.0
make falco-plugin
```

### Use the plugin

```
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco \
    --namespace falco --create-namespace \
    --set-string driver.kind=modern-bpf \
    --set-string \
        falcoctl.config.artifact.allowedTypes='{rulesfile,plugin}' \
    --set-string \
        falcoctl.config.artifact.install.refs='{albantest.azurecr.io/falco-plugin-ig:0.1.0,albantest.azurecr.io/falco-plugin-ig-ruleset:0.1.0}' \
    --set-string \
        falco.load_plugins='{ig}' \
    --set-string falco.plugins[0].name=ig \
    --set-string falco.plugins[0].library_path=libfalco-plugin-ig.so \
    --set-string falco.plugins[0].init_config.gadget=mygadget \
    --set-string \
        falco.rules_file='{/etc/falco/ig_rules.yaml}' \
    --set-string mounts.volumes[0].name='tracefs' \
    --set-string mounts.volumes[0].hostPath.path='/sys/kernel/tracing' \
    --set-string mounts.volumeMounts[0].name='tracefs' \
    --set-string mounts.volumeMounts[0].mountPath='/sys/kernel/tracing'

kubectl logs $(kubectl get pod -n falco -o name) -n falco

helm uninstall falco -n falco
```

## Limitations

- Events need to fit in 256KB (`sdk.DefaultEvtSize`) once encoded in json.
