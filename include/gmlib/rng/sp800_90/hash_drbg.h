// NIST SP 800 90
#ifndef RNG_SP800_90_HASH_DRBG_H
#define RNG_SP800_90_HASH_DRBG_H

#include <gmlib/hash_lib/hash.h>
#include <gmlib/memory_utils/endian.h>
#include <gmlib/rng/rng.h>
#include <gmlib/rng/sp800_90/internal/bn.h>
#include <gmlib/rng/sp800_90/internal/entropy.h>

#include <cstring>

namespace rng::sp800_90 {

/**
 * @brief   Unlike the standard of NIST SP 800 90A, the length here is in bytes,
 *          which is different from the length in bits in the standard
 * @tparam  Hash
 */
template <class Hash>
class HashDrbg : public Rng
{
    static_assert(hash_lib::type_traits::is_valid_hash<Hash>::value,
                  "invalid hash class");

public:
    /// @brief Minimum entropy input length (in bytes)
    static constexpr std::size_t MINIMUM_ENTROPY = Hash::SECURITY_STRENGTH;

    /// @brief Maximum entropy input length (in bytes):  2^32 bytes
    static constexpr std::uint64_t MAXIMUM_ENTROPY = (1ULL << 32);

    /// @brief Maximum personalization string length (in bytes): 2^32 bytes
    static constexpr std::uint64_t MAXIMUM_PERSONALIZATION = (1ULL << 32);

    /// @brief Maximum additional_input length (in bytes): 2^32 bytes
    static constexpr std::uint64_t MAXIMUM_ADDITIONAL = (1ULL << 32);

    static constexpr std::uint32_t MAXIMUM_BYTES_PER_REQUEST = (1ULL << 16);

    /// @brief Maximum number of requests: 2^48
    static constexpr std::uint64_t MAXIMUM_REQUESTS_BEFORE_RESEED =
        (1ULL << 48);

    /// @brief Seed length (in bytes)
    static constexpr std::size_t SEED_LEN =
        (Hash::DIGEST_SIZE <= 32) ? 55 : 111;

    /// @brief Output Block Length (in bytes)
    static constexpr std::size_t OUT_BLOCK_LEN = Hash::DIGEST_SIZE;

private:
    std::uint8_t  V_[HashDrbg::SEED_LEN];
    std::uint8_t  C_[HashDrbg::SEED_LEN];
    std::uint64_t reseed_counter_;

    /// @brief  32-bit incrementing counter is used as the nonce for
    /// instantiation (instantiation_nonce); the nonce is initialized when the
    /// DRBG is instantiated (e.g., by a call to the clock or by setting it to a
    /// fixed value) and is incremented for each instantiation
    std::uint32_t instantiation_nonce_;

public:
    inline HashDrbg();

    inline ~HashDrbg() noexcept = default;

private:
    /**
     * @brief       Derivation Function Using a Hash Function, NIST SP 800 90A
     * @param[out]  requested_bytes
     *                  The result of performing the Hash_df
     * @param[in]   input_string
     *                  The string to be hashed, a list
     * @param[in]   input_string_length
     *                  length in bytes, a list
     * @param[in]   input_string_num
     *                  number of input string, that means, input string is
     *                  input_string[0] || input_string[1] || ... ||
     *                  input_string[input_string_num -1]
     * @param[in]   no_of_bytes_to_return
     *                  The number of bytes to be returned by Hash_df. The
     *                  maximum length (max_number_of_bytes) is implementation
     *                  dependent, but shall be less than or equal to (255 x
     *                  OUT_BLOCK_LEN). no_of_bytes_to_return is represented as
     *                  a 32-bit integer
     */
    static inline void hash_df(std::uint8_t*       requested_bytes,
                               const std::uint8_t* input_string[],
                               const std::size_t   input_string_length[],
                               std::size_t         input_string_num,
                               std::size_t         no_of_bytes_to_return);

    /**
     * @brief       Hashgen
     * @param[out]  returned_bytes
     *                  The generated bytes to be returned to the generate
     *                  function
     * @param[in]   no_of_bytes_to_return
     *                  The number of bytes to be returned
     * @param[in]   V
     *                  The current value of V, length in 'SEED_LEN'
     */
    static inline void hashgen(std::uint8_t*       returned_bytes,
                               std::size_t         no_of_bytes_to_return,
                               const std::uint8_t* V);

public:
    /**
     * @brief       Hash_DRBG_Instantiate_algorithm
     * @param[in]   entropy_input
     *                  The string of bytes obtained from the randomness source
     * @param[in]   entropy_input_length
     *                  length in bytes
     * @param[in]   nonce
     *                  A string of bytes
     * @param[in]   nonce_length
     *                  length in bytes
     * @param[in]   personalization_string
     *                  The personalization string received from the consuming
     *                  application. Note that the length of the
     *                  personalization_string may be zero
     * @param[in]   personalization_string_length
     *                  length in bytes
     * @param[in]   security_strength
     *                  The security strength for the instantiation. This
     *                  parameter is optional for Hash_DRBG, since it is not
     *                  used
     */
    inline void instantiate(const std::uint8_t* entropy_input,
                            std::size_t         entropy_input_length,
                            const std::uint8_t* nonce,
                            std::size_t         nonce_length,
                            const std::uint8_t* personalization_string,
                            std::size_t         personalization_string_length,
                            std::size_t         security_strength);

    /**
     * @brief       Hash_DRBG_Reseed_algorithm
     * @param[in]   entropy_input
     *                  The string of bytes obtained from the randomness source
     * @param[in]   entropy_input_length
     *                  length in bytes
     * @param[in]   additional_input
     *                  The additional input string received from the consuming
     *                  application. Note that the length of the
     *                  additional_input string may be zero
     * @param[in]   additional_input_length
     *                  length in bytes
     */
    inline void reseed(const std::uint8_t* entropy_input,
                       std::size_t         entropy_input_length,
                       const std::uint8_t* additional_input,
                       std::size_t         additional_input_length);

    /**
     * @brief       Hash_DRBG_Generate_algorithm
     * @param[out]  returned_bytes
     *                  The pseudorandom bytes to be returned to the generate
     *                  function
     * @param[in]   requested_number_of_bytes
     *                  The number of pseudorandom bytes to be returned to the
     *                  generate function
     * @param[in]   additional_input
     *                  The additional input string received from the consuming
     *                  application. Note that the length of the
     *                  additional_input string may be zero
     * @param[in]   additional_input_length
     *                  length in bytes
     * @return          0(Success), -1(error, need to reseed)
     */
    inline int generate(std::uint8_t*       returned_bytes,
                        std::size_t         requested_number_of_bytes,
                        const std::uint8_t* additional_input,
                        std::size_t         additional_input_length);

public:
    const char* name() const noexcept override
    {
        return "HashDrbg";
    }

    inline void gen(void* out, std::size_t len) override;
};

template <class Hash>
inline HashDrbg<Hash>::HashDrbg()
{
    std::uint8_t entropy[HashDrbg<Hash>::MINIMUM_ENTROPY];
    std::uint8_t nonce[4];
    internal::get_entropy(nonce, sizeof(nonce));
    instantiation_nonce_ = memory_utils::load32_be(nonce);
    internal::get_entropy(entropy, sizeof(entropy));
    this->instantiate(entropy, sizeof(entropy), nonce, 4, nullptr, 0,
                      Hash::SECURITY_STRENGTH);
}

template <class Hash>
inline void HashDrbg<Hash>::gen(void* out, std::size_t len)
{
    std::uint8_t  entropy[HashDrbg<Hash>::MINIMUM_ENTROPY];
    std::uint8_t* data_u8ptr = (std::uint8_t*)out;
    int           ret;
    while (len >= HashDrbg<Hash>::MAXIMUM_BYTES_PER_REQUEST)
    {
        ret = this->generate(                          //
            data_u8ptr,                                //
            HashDrbg<Hash>::MAXIMUM_BYTES_PER_REQUEST, //
            nullptr,                                   //
            0                                          //
        );
        if (ret == -1) // unlikely
        {
            internal::get_entropy(entropy, sizeof(entropy));
            this->reseed(entropy, sizeof(entropy), nullptr, 0);
        }
        else
        {
            data_u8ptr += HashDrbg<Hash>::MAXIMUM_BYTES_PER_REQUEST;
            len -= HashDrbg<Hash>::MAXIMUM_BYTES_PER_REQUEST;
        }
    }
    if (len > 0)
    {
        ret = this->generate(data_u8ptr, len, nullptr, 0);
        if (ret == -1) // unlikely
        {
            internal::get_entropy(entropy, sizeof(entropy));
            this->reseed(entropy, sizeof(entropy), nullptr, 0);
            this->generate(data_u8ptr, len, nullptr, 0); // never fail
        }
    }
}

// ==================================================

template <class Hash>
inline void HashDrbg<Hash>::hash_df(std::uint8_t*       requested_bytes,
                                    const std::uint8_t* input_string[],
                                    const std::size_t   input_string_length[],
                                    std::size_t         input_string_num,
                                    std::size_t         no_of_bytes_to_return)
{
    std::uint8_t counter = 0x01;
    std::uint8_t buf_no_of_bytes_to_return[4], buf[Hash::DIGEST_SIZE];
    Hash         hash_ctx;
    // len = ceil(no_of_bytes_to_return / OUT_BLOCK_LEN)
    // FOR i = 1 to len
    memory_utils::store32_be(buf_no_of_bytes_to_return,
                             (std::uint32_t)no_of_bytes_to_return);
    while (no_of_bytes_to_return >= Hash::DIGEST_SIZE)
    {
        // Hash (counter || no_of_bits_to_return || input_string)
        hash_ctx.reset();
        hash_ctx.update(&counter, 1);
        hash_ctx.update(buf_no_of_bytes_to_return, 4);
        for (std::size_t i = 0; i < input_string_num; i++)
        {
            hash_ctx.update(input_string[i], input_string_length[i]);
        }
        hash_ctx.do_final(requested_bytes);
        // update
        counter += 1;
        requested_bytes += Hash::DIGEST_SIZE;
        no_of_bytes_to_return -= Hash::DIGEST_SIZE;
    }
    if (no_of_bytes_to_return)
    {
        hash_ctx.reset();
        hash_ctx.update(&counter, 1);
        hash_ctx.update(buf_no_of_bytes_to_return, 4);
        for (std::size_t i = 0; i < input_string_num; i++)
        {
            hash_ctx.update(input_string[i], input_string_length[i]);
        }
        hash_ctx.do_final(buf);

        std::memcpy(requested_bytes, buf, no_of_bytes_to_return);
    }
}

template <class Hash>
inline void HashDrbg<Hash>::hashgen(std::uint8_t*       returned_bytes,
                                    std::size_t         no_of_bytes_to_return,
                                    const std::uint8_t* V)
{
    static const std::uint8_t ONE = 1;

    Hash         hash;
    std::uint8_t digest[Hash::DIGEST_SIZE];
    std::uint8_t data[HashDrbg<Hash>::SEED_LEN];
    // 1. m = ceil(requested_no_of_bits / outlen)
    // 2. data = V
    // 3. W = Null String
    std::memcpy(data, V, HashDrbg<Hash>::SEED_LEN);
    // 4. For i = 1 to m
    while (no_of_bytes_to_return >= Hash::DIGEST_SIZE)
    {
        // 4.1 w = Hash(data)
        // 4.2 W = W || w
        hash.reset();
        hash.do_final(returned_bytes, data, sizeof(data));
        // 4.3 data = (data + 1) mod 2^seedlen
        internal::bn_self_add(data, sizeof(data), &ONE, 1);

        no_of_bytes_to_return -= Hash::DIGEST_SIZE;
        returned_bytes += Hash::DIGEST_SIZE;
    }
    if (no_of_bytes_to_return)
    {
        hash.reset();
        hash.do_final(digest, data, sizeof(data));
        std::memcpy(returned_bytes, digest, no_of_bytes_to_return);
    }
    // 5. returned_bits = leftmost(W, requested_no_of_bits)
    // 6. Return(returned_bits)
}

template <class Hash>
inline void HashDrbg<Hash>::instantiate(
    const std::uint8_t* entropy_input,
    std::size_t         entropy_input_length,
    const std::uint8_t* nonce,
    std::size_t         nonce_length,
    const std::uint8_t* personalization_string,
    std::size_t         personalization_string_length,
    std::size_t         security_strength)
{
    static std::uint8_t zero = 0x00;
    const std::uint8_t* input_string[3];
    std::size_t         input_string_length[3];

    // seed_material = entropy_input || nonce || personalization_string
    // seed = Hash_df (seed_material, SEED_LEN)
    // V = seed
    input_string[0]        = entropy_input;
    input_string_length[0] = entropy_input_length;
    input_string[1]        = nonce;
    input_string_length[1] = nonce_length;
    input_string[2]        = personalization_string;
    input_string_length[2] = personalization_string_length;
    this->hash_df(V_, input_string, input_string_length, 3,
                  HashDrbg<Hash>::SEED_LEN);
    // C = Hash_df ((0x00 || V), SEED_LEN)
    input_string[0]        = &zero;
    input_string_length[0] = 1;
    input_string[1]        = V_;
    input_string_length[1] = HashDrbg<Hash>::SEED_LEN;
    this->hash_df(C_, input_string, input_string_length, 2,
                  HashDrbg<Hash>::SEED_LEN);
    // reseed_counter = 1
    reseed_counter_ = 1;
}

template <class Hash>
inline void HashDrbg<Hash>::reseed(const std::uint8_t* entropy_input,
                                   std::size_t         entropy_input_length,
                                   const std::uint8_t* additional_input,
                                   std::size_t         additional_input_length)
{
    static const std::uint8_t ZERO = 0x00, ONE = 0x01;

    std::uint8_t        V_buf[HashDrbg<Hash>::SEED_LEN];
    const std::uint8_t* input_string[4];
    std::size_t         input_string_length[4];

    // seed_material = 0x01 || V || entropy_input || additional_input
    // seed = Hash_df (seed_material, SEED_LEN)
    // V = seed
    std::memcpy(V_buf, V_, HashDrbg<Hash>::SEED_LEN);
    input_string[0]        = &ONE;
    input_string_length[0] = 1;
    input_string[1]        = V_buf;
    input_string_length[1] = HashDrbg<Hash>::SEED_LEN;
    input_string[2]        = entropy_input;
    input_string_length[2] = entropy_input_length;
    input_string[3]        = additional_input;
    input_string_length[3] = additional_input_length;
    this->hash_df(V_, input_string, input_string_length, 4,
                  HashDrbg<Hash>::SEED_LEN);
    // C = Hash_df ((0x00 || V), SEED_LEN)
    input_string[0]        = &ZERO;
    input_string_length[0] = 1;
    input_string[1]        = V_;
    input_string_length[1] = HashDrbg<Hash>::SEED_LEN;
    this->hash_df(C_, input_string, input_string_length, 2,
                  HashDrbg<Hash>::SEED_LEN);
    // reseed_counter = 1
    reseed_counter_ = 1;
}

template <class Hash>
inline int HashDrbg<Hash>::generate( //
    std::uint8_t*       returned_bytes,
    std::size_t         requested_number_of_bytes,
    const std::uint8_t* additional_input,
    std::size_t         additional_input_length)
{
    static const std::uint8_t TWO   = 0x02;
    static const std::uint8_t THREE = 0x03;

    Hash         hash;
    std::uint8_t w[Hash::DIGEST_SIZE], buf_cnt[8];
    // 1. If reseed_counter > MAXIMUM_REQUESTS_BEFORE_RESEED, then return an
    // indication that a
    //    reseed is required
    if (reseed_counter_ > HashDrbg<Hash>::MAXIMUM_REQUESTS_BEFORE_RESEED)
    {
        return -1;
    }
    // 2.If (additional_input != Null), then do
    //    2.1 w = Hash (0x02 || V || additional_input)
    //    2.2 V = (V + w) mod 2^SEED_LEN_bits
    if (additional_input != nullptr)
    {
        hash.update(&TWO, 1);
        hash.update(V_, HashDrbg<Hash>::SEED_LEN);
        hash.update(additional_input, additional_input_length);
        hash.do_final(w);
        internal::bn_self_add(V_, HashDrbg<Hash>::SEED_LEN, //
                              w, Hash::DIGEST_SIZE);
        hash.reset();
    }
    // 3. (returned_bits) = Hashgen (requested_number_of_bits, V)
    this->hashgen(returned_bytes, requested_number_of_bytes, V_);
    // 4. H = Hash (0x03 || V)
    hash.update(&THREE, 1);
    hash.update(V_, HashDrbg<Hash>::SEED_LEN);
    hash.do_final(w);
    // 5. V = (V + H + C + reseed_counter) mod 2^SEED_LEN
    memory_utils::store64_be(buf_cnt, reseed_counter_);
    internal::bn_self_add(V_, HashDrbg<Hash>::SEED_LEN, //
                          w, Hash::DIGEST_SIZE);
    internal::bn_self_add(V_, HashDrbg<Hash>::SEED_LEN, //
                          C_, HashDrbg<Hash>::SEED_LEN);
    internal::bn_self_add(V_, HashDrbg<Hash>::SEED_LEN, //
                          buf_cnt, sizeof(buf_cnt));
    // 6. reseed_counter = reseed_counter + 1
    reseed_counter_ += 1;
    return 0;
}

} // namespace rng::sp800_90

#endif