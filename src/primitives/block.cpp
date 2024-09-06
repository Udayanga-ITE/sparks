// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016-2022 The Sparks Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <streams.h>
#include <tinyformat.h>
#include <crypto/common.h>
#include <crypto/neoscrypt.h>
#include <crypto/randomx/randomx.h>

// Size of RandomX hash output
const int HASH_SIZE = 32;

// Function to initialize RandomX cache
randomx_cache* initializeRandomXCache(const void* key, size_t keySize) {
    randomx_cache *cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
    if (cache == nullptr) {
        std::cerr << "Failed to allocate RandomX cache." << std::endl;
        exit(EXIT_FAILURE);
    }

    // Initialize cache with key (can be a seed or unique identifier for the block)
    randomx_init_cache(cache, key, keySize);
    return cache;
}

// Function to initialize RandomX dataset (optional but speeds up mining on large datasets)
randomx_dataset* initializeRandomXDataset(randomx_cache* cache) {
    randomx_dataset *dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
    if (dataset == nullptr) {
        std::cerr << "Failed to allocate RandomX dataset." << std::endl;
        exit(EXIT_FAILURE);
    }

    // Populate dataset (you can do this over a range of items)
    uint32_t startItem = 0;
    uint32_t itemCount = randomx_dataset_item_count();
    randomx_init_dataset(dataset, cache, startItem, itemCount);
    return dataset;
}

// Function to mine with RandomX
void mineWithRandomX(const void* input, size_t inputSize, uint8_t* hash_output) {
    // Step 1: Create a key or seed (example: using static key)
    const char* key = "my_randomx_seed";
    size_t keySize = strlen(key);

    // Step 2: Initialize RandomX cache
    randomx_cache *cache = initializeRandomXCache(key, keySize);

    // Step 3 (Optional): Initialize RandomX dataset (only if you need to use a dataset)
    // randomx_dataset *dataset = initializeRandomXDataset(cache);

    // Step 4: Create RandomX VM with the cache (flags can include JIT, AES, etc.)
    randomx_vm *vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_JIT, cache, nullptr);
    if (vm == nullptr) {
        std::cerr << "Failed to create RandomX VM." << std::endl;
        randomx_release_cache(cache);
        exit(EXIT_FAILURE);
    }

    // Step 5: Calculate the hash
    randomx_calculate_hash(vm, input, inputSize, hash_output);

    // Step 6: Destroy the VM and clean up
    randomx_destroy_vm(vm);
    randomx_release_cache(cache);
    // If you used a dataset, remember to release it
    // randomx_release_dataset(dataset);
}

uint256 CBlockHeader::GetHash() const
{
        uint256 thash;
        unsigned int profile = 0x0;
        neoscrypt((unsigned char *) &nVersion, (unsigned char *) &thash, profile);
        return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

static void MarkVersionAsMostRecent(std::list<int32_t>& last_unique_versions, std::list<int32_t>::const_iterator version_it)
{
    if (version_it != last_unique_versions.cbegin()) {
        // Move the found version to the front of the list
        last_unique_versions.splice(last_unique_versions.begin(), last_unique_versions, version_it, std::next(version_it));
    }
}

static void SaveVersionAsMostRecent(std::list<int32_t>& last_unique_versions, const int32_t version)
{
    last_unique_versions.push_front(version);

    // Always keep the last 7 unique versions
    constexpr std::size_t max_backwards_look_ups = 7;
    if (last_unique_versions.size() > max_backwards_look_ups) {
        // Evict the oldest version
        last_unique_versions.pop_back();
    }
}

void CompressibleBlockHeader::Compress(const std::vector<CompressibleBlockHeader>& previous_blocks, std::list<int32_t>& last_unique_versions)
{
    if (previous_blocks.empty()) {
        // Previous block not available, we have to send the block completely uncompressed
        SaveVersionAsMostRecent(last_unique_versions, nVersion);
        return;
    }

    // Try to compress version
    const auto version_it = std::find(last_unique_versions.cbegin(), last_unique_versions.cend(), nVersion);
    if (version_it != last_unique_versions.cend()) {
        // Version is found in the last 7 unique blocks.
        bit_field.SetVersionOffset(static_cast<uint8_t>(std::distance(last_unique_versions.cbegin(), version_it) + 1));

        // Mark the version as the most recent one
        MarkVersionAsMostRecent(last_unique_versions, version_it);
    } else {
        // Save the version as the most recent one
        SaveVersionAsMostRecent(last_unique_versions, nVersion);
    }

    // Previous block is available
    const auto& last_block = previous_blocks.back();
    bit_field.MarkAsCompressed(CompressedHeaderBitField::Flag::PREV_BLOCK_HASH);

    // Compute compressed time diff
    const int64_t time_diff = nTime - last_block.nTime;
    if (time_diff <= std::numeric_limits<int16_t>::max() && time_diff >= std::numeric_limits<int16_t>::min()) {
        time_offset = static_cast<int16_t>(time_diff);
        bit_field.MarkAsCompressed(CompressedHeaderBitField::Flag::TIMESTAMP);
    }

    // If n_bits matches previous block, it can be compressed (not sent at all)
    if (nBits == last_block.nBits) {
        bit_field.MarkAsCompressed(CompressedHeaderBitField::Flag::NBITS);
    }
}

void CompressibleBlockHeader::Uncompress(const std::vector<CBlockHeader>& previous_blocks, std::list<int32_t>& last_unique_versions)
{
    if (previous_blocks.empty()) {
        // First block in chain is always uncompressed
        SaveVersionAsMostRecent(last_unique_versions, nVersion);
        return;
    }

    // We have the previous block
    const auto& last_block = previous_blocks.back();

    // Uncompress version
    if (bit_field.IsVersionCompressed()) {
        const auto version_offset = bit_field.GetVersionOffset();
        if (version_offset <= last_unique_versions.size()) {
            auto version_it = last_unique_versions.begin();
            std::advance(version_it, version_offset - 1);
            nVersion = *version_it;
            MarkVersionAsMostRecent(last_unique_versions, version_it);
        }
    } else {
        // Save the version as the most recent one
        SaveVersionAsMostRecent(last_unique_versions, nVersion);
    }

    // Uncompress prev block hash
    if (bit_field.IsCompressed(CompressedHeaderBitField::Flag::PREV_BLOCK_HASH)) {
        hashPrevBlock = last_block.GetHash();
    }

    // Uncompress timestamp
    if (bit_field.IsCompressed(CompressedHeaderBitField::Flag::TIMESTAMP)) {
        nTime = last_block.nTime + time_offset;
    }

    // Uncompress n_bits
    if (bit_field.IsCompressed(CompressedHeaderBitField::Flag::NBITS)) {
        nBits = last_block.nBits;
    }
}
