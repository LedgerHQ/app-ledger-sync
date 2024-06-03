# Fuzzing on transaction parser

## Compilation

In `fuzzing` folder

```shell
cmake -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -Bbuild -H.
```

then

```shell
make -C build
```

## Run

```shell
./build/fuzz_tx_parser
```
