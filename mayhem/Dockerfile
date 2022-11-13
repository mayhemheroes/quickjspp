FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install

WORKDIR /repo/quickjs/build
RUN cmake .. 
RUN make -j8

WORKDIR /repo
RUN clang++ mayhem/fuzz_eval.cpp  -fsanitize=address,fuzzer -std=c++17 -lquickjs -L /repo/quickjs/build/  -I /repo/quickjs -I /install/include/ -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /fuzz /fuzz_eval
COPY --from=builder /install /install
