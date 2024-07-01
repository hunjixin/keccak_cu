# keccak cuda hash

implemation of paper https://www.researchgate.net/publication/220849942_GPU_Implementation_of_the_Keccak_Hash_Function_Family.
also do some improvement with asm.


performance: test on 3060ti         1400M hash/s

command

build ptx
```
cd gpulib
nvcc --ptx .\keccak.cu -o ./keccak.ptx
```

run bench
```
cd gputool
go build

./gputool --hash_per_thread 1000 --grid <smcount*2> //default difficult nearly cannot find the nonce
./gputool --hash_per_thread 1000 --grid <smcount*2> --difficulty 4443685057045916916839494277496125038705878205143482420972918669312  //expect to finis with 6 minitus for 1000m hash spped
```