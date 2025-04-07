#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <span>
#include <cstdint>
#include "regular_dpf.h"
// Include the actual C++ implementation
#include "libOTe/Dpf/RegularDpf.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h" // For block type
#include "cryptoTools/Crypto/PRNG.h"  // For PRNG class

// Write helper function to create a C++ span from array and length info, given type T
template<typename T>
std::span<T> make_span_from_data(T* arr, size_t length) {
    return std::span<T>(arr, length);
}

extern "C"
{

    int simple_function() {
        return 0;
    };

    int example_span() {
        int numbers[] = {1, 2, 3, 4, 5};
        std::span<int> numberSpan = make_span_from_data(numbers, 5);
        // increase each number by 1
        for (size_t i = 0; i < numberSpan.size(); ++i) {
            numberSpan[i] += 1;
        }
        // return the last number
        return numberSpan[4];
    };

    void keyGen(
        u64 domain,
        u64* points, 
        u8* values,
        u64 numPoints,
        u64 prngSeed, // type PRNG& in C++ verison
        u64* keySize,
        u8* keyOut0,
        u8* keyOut1)
    {
        // POINTS CAST -- Convert C array to C++ span
        std::span<u64> pointsSpan = make_span_from_data(points, numPoints);

        // VALUES CAST -- Cast the u8* values to std::span<osuCrypto::block>
        std::span<osuCrypto::block> valuesSpan = make_span_from_data(reinterpret_cast<osuCrypto::block*>(values), numPoints);

        // TODO do more like this, use the seed given
        // osuCrypto::PRNG prng;
        // prng.SetSeed(prngSeed);
        // Make a PRNG and set its seed
        osuCrypto::PRNG prng(osuCrypto::block(prngSeed, 0)); 
        
        // OUTPUT KEYS -- Create temporary C++ keys
        std::array<osuCrypto::RegularDpfKey, 2> cppKeys;
        
        // KEYGEN -- Call the C++ implementation
        osuCrypto::RegularDpf::keyGen(domain, pointsSpan, valuesSpan, prng, cppKeys);

        // get the size of cppKeys, store in output to report the real keySize
        *keySize = cppKeys[0].sizeBytes();

        // Cast key output buffers as span<u8> 
        std::span<u8> key0 = make_span_from_data(keyOut0, (*keySize));
        std::span<u8> key1 = make_span_from_data(keyOut1, (*keySize));

        // Copy the keys to the output
        cppKeys[0].toBytes(key0);
        cppKeys[1].toBytes(key1);
    }
    
    // Example implementation for expand using a function pointer callback approach
    void expand(
        u64 partyIdx,
        u64 domain,
        u64 numPoints,
        u8* key,
        u64 keySize,
        u8* expandedKey)
    {
        if (numPoints != 1) {
            throw std::invalid_argument("numPoints can only be 1 for now...single point DPFs only");
        }

        osuCrypto::Matrix<osuCrypto::block> output;
        output.resize(numPoints, domain);

        // Unclear what tags is actually needed for...
        osuCrypto::Matrix<u8> tags;
        tags.resize(numPoints, domain);

        // Initialize key
        osuCrypto::RegularDpfKey keyExp;
        keyExp.resize(domain, numPoints);
        std::span<u8> keySpan(reinterpret_cast<u8*>(key), keySize);
        keyExp.fromBytes(keySpan);

        osuCrypto::RegularDpf::expand(partyIdx, domain, keyExp, [&](auto k, auto i, auto v, osuCrypto::block t) { output(k, i) = v; tags(k, i) = t.get<u8>(0) & 1; });

        // SAVE in case I implement for multi-point...
        // for (u64 i = 0; i < domain; ++i)
        // {
        //     for (u64 k = 0; k < numPoints; ++k)
        //     {
        //         osuCrypto::block act = output[k][i];
        //         // copy every byte of block
        //         std::memcpy(expandedKey + 16*(k*domain+i), &act, 16); 
        //     }
        // }

        std::memcpy(expandedKey, output[0].data(), 16 * domain);

    }

    void multiplyDB(
        u8* keyExp,
        u8* DB,
        u8* out,
        int length) 
    {

        // init outBlock to zero
        osuCrypto::block outBlock = osuCrypto::block(0,0); // ZeroBlock

        // iterate block by block
        for (int i = 0; i < length; ++i) {
            // copy the block from keyExp
            osuCrypto::block keyBlock;
            std::memcpy(&keyBlock, keyExp + 16*i, 16); 

            // copy the block from DB
            osuCrypto::block dbBlock;
            std::memcpy(&dbBlock, DB + 16*i, 16); 

            osuCrypto::block res = keyBlock.gf128Mul(dbBlock); 

            // xor with the out block
            outBlock = outBlock ^ res;

        }

        // copy the out block to the output
        std::memcpy(out, &outBlock, 16); 
    }

    void gfmul(
        u8* x,
        u8* y,
        u8* out)
    {
        osuCrypto::block xBlock;
        std::memcpy(&xBlock, x, 16); 

        osuCrypto::block yBlock;
        std::memcpy(&yBlock, y, 16); 

        osuCrypto::block res = xBlock.gf128Mul(yBlock); 

        std::memcpy(out, &res, 16); 
    }
    
} // close extern "C"