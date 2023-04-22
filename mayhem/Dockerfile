# Build Stage
FROM --platform=linux/amd64 ubuntu:22.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake libssl-dev

## Add source code to the build stage.
ADD . /src

## Build
WORKDIR /src
RUN CC=clang make FUZZING=1 && make install
RUN ldconfig

# Package Stage
FROM --platform=linux/amd64 ubuntu:22.04
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y libssl3:amd64
COPY --from=builder /src/fuzz_pe /fuzz_pe
COPY --from=builder /usr/local/lib/libpe.so.1 /usr/local/lib/libpe.so.1
RUN ldconfig

# Set up fuzzing!
ENTRYPOINT []
CMD /fuzz_pe
