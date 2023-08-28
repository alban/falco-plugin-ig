# Use the same base image as falco to ensure compatibility with glibc version
FROM golang:buster as builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /src/
RUN cd /src && go mod download

COPY ./ /src
RUN cd /src && make

FROM falcosecurity/falco-no-driver:0.35.1

SHELL ["/bin/bash", "-c"]

COPY falco-config-plugin-snippet.yaml /etc/falco/
COPY ig_rules.yaml /etc/falco/rules.d/

RUN \
    SNIPPET="$(jq -Rs . < /etc/falco/falco-config-plugin-snippet.yaml)" && \
    SNIPPET="${SNIPPET:1}" && \
    SNIPPET="${SNIPPET/%?/}" && \
	sed -i \
	-e '/^plugins:$/a \'"$SNIPPET" \
	-e 's/^load_plugins:.*$/load_plugins: [ig]/' \
	/etc/falco/falco.yaml && \
    rm -f /etc/falco/falco-config-plugin-snippet.yaml
COPY --from=builder /src/libfalco-plugin-ig.so /usr/share/falco/plugins/

