# dpf128-go

Golang wrapper functions which call [osu-crypto/libOTe](https://github.com/osu-crypto/libOTe/tree/master)'s distributed point function (DPF) module, which works over the field $GF(2^{128})$. 

Note libOTe has richer DPF functionality than exposed in Golang here. This code exposes the single-point DPFs with static key generation as a Golang module. 

### Dependencies & Setup

1. Golang 1.23

2. Python

3. `osu-crypto/libOTe`

    1. Clone libOTe, then make directory `mkdir test`
    2. Build libOTe to expose the DPF functionality as a shared library with:  
       `python build.py -DENABLE_REGULAR_DPF=ON  -DENABLE_PIC=ON -DLIBOTE_SHARED=ON --install=test`
    3. Update paths to `test` at the top of `modules/osu-crypto/osu_dpf.go`


#### Acknowledgement: Thank you to Peter Rindal for his help while working with his `osu-crypto/libOTe` library