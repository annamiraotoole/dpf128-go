#include <stdint.h>
#include <stddef.h>  // for size_t


#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////////////////////////////////
// TYPES
//////////////////////////////////////////////////////////////////////////////

// alias for u8
typedef uint8_t u8;
typedef uint64_t u64;

//////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
//////////////////////////////////////////////////////////////////////////////

int simple_function();

int example_span();

/**
 * Generates a pair of DPF keys.
 * domain: The size of the evaluation domain.
 * points: The plaintext list of locations to encode.
 * values: The plaintext list of values to encode at the specified locations.
 * numPoints: The number of non-zero points / number of DPF keys (should be 1)
 * prngSeed: Seed for the source of randomness
 * keySize: Output parameter: Memory to store the size of one DPF key
 * keysOut: Output parameter: The two generated DPF keys. (length = keySize * 2)
 */
void keyGen(
    u64 domain,
    u64* points, 
    u8* values,
    u64 numPoints,
    u64 prngSeed, // type PRNG& in C++ verison
    u64* keySize,
    u8* keyOut0,
    u8* keyOut1);


/**
 * Performs non-interactive full domain evaluation.
 * partyIdx: This party's index (0 or 1).
 * domain: The size of the evaluation domain.
 * numPoints: The number of points to evaluate. (should be 1, since singlepoint DPFs)
 * key: This party's share of the FSS key.
 * keySize: The size of the key in bytes.
 * expandedKey: Buffer for the expanded key to be written into.
 */
void expand(
    u64 partyIdx,
    u64 domain,
    u64 numPoints,
    u8* key,
    u64 keySize,
    u8* expandedKey);


void multiplyDB(
    u8* keyExp,
    u8* DB,
    u8* out,
    int length);

void gfmul(
    u8* x,
    u8* y,
    u8* out);   


#ifdef __cplusplus
}
#endif