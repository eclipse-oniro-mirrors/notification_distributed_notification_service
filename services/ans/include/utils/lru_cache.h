/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_LRU_CACHE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_LRU_CACHE_H

#include <list>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <vector>
#include <algorithm>

namespace OHOS {
namespace Notification {

/**
 * @brief Standard LRU (Least Recently Used) cache implementation.
 *
 * Features:
 * - O(1) lookup, insert, and delete operations
 * - Automatic eviction of least recently used items
 * - Configurable capacity limit and TTL (Time To Live)
 * - Built-in cache hit/miss statistics
 *
 * @tparam K Key type
 * @tparam V Value type
 */
template <typename K, typename V>
class LRUCache {
public:
    struct Node {
        V value;
        typename std::list<K>::iterator listIt;
    };

    using Clock = std::chrono::steady_clock;
    using TimePoint = std::chrono::steady_clock::time_point;

    struct Config {
        size_t maxSize = 100;
        std::chrono::minutes ttl = std::chrono::minutes(5);
        bool enableTTL = true;
    };

    struct Stats {
        size_t hits = 0;
        size_t misses = 0;
        size_t evictions = 0;
        size_t expires = 0;
        double HitRate() const
        {
            size_t total = hits + misses;
            return total > 0 ? static_cast<double>(hits) / total : 0.0;
        }
    };

    explicit LRUCache(const Config& config = {}) : config_(config) {}

    LRUCache(const LRUCache& other)
        : config_(other.config_),
          lruList_(other.lruList_),
          cache_(other.cache_),
          nodeTimestamps_(other.nodeTimestamps_),
          hitCount_(other.hitCount_),
          missCount_(other.missCount_),
          evictCount_(other.evictCount_),
          expireCount_(other.expireCount_)
    {
        for (auto& entry : cache_) {
            auto it = std::find(lruList_.begin(), lruList_.end(), entry.first);
            if (it != lruList_.end()) {
                entry.second.listIt = it;
            }
        }
    }

    LRUCache& operator=(const LRUCache& other)
    {
        if (this != &other) {
            config_ = other.config_;
            lruList_ = other.lruList_;
            cache_ = other.cache_;
            nodeTimestamps_ = other.nodeTimestamps_;
            hitCount_ = other.hitCount_;
            missCount_ = other.missCount_;
            evictCount_ = other.evictCount_;
            expireCount_ = other.expireCount_;
            for (auto& entry : cache_) {
                auto it = std::find(lruList_.begin(), lruList_.end(), entry.first);
                if (it != lruList_.end()) {
                    entry.second.listIt = it;
                }
            }
        }
        return *this;
    }

    /**
     * @brief Lookup and mark as most recently accessed.
     * @param key The key to lookup.
     * @param value Output value if found.
     * @return true if found, false otherwise.
     */
    bool Get(const K& key, V& value)
    {
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            ++missCount_;
            return false;
        }
        if (config_.enableTTL) {
            auto age = Clock::now() - nodeTimestamps_[key];
            if (age > config_.ttl) {
                Remove(key);
                ++expireCount_;
                return false;
            }
        }
        Touch(it);
        value = it->second.value;
        ++hitCount_;
        return true;
    }

    /**
     * @brief Lookup without updating access time.
     * @param key The key to lookup.
     * @param value Output value if found.
     * @return true if found, false otherwise.
     */
    bool Peek(const K& key, V& value)
    {
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            return false;
        }
        if (config_.enableTTL) {
            auto tsIt = nodeTimestamps_.find(key);
            if (tsIt != nodeTimestamps_.end()) {
                auto age = Clock::now() - tsIt->second;
                if (age > config_.ttl) {
                    Remove(key);
                    ++expireCount_;
                    return false;
                }
            }
        }
        value = it->second.value;
        return true;
    }

    /**
     * @brief Insert or update a key-value pair.
     * @param key The key.
     * @param value The value (rvalue reference).
     */
    void Put(const K& key, V&& value)
    {
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            it->second.value = std::move(value);
            Touch(it);
            nodeTimestamps_[key] = Clock::now();
            return;
        }
        EvictExpired();
        if (cache_.size() >= config_.maxSize) {
            EvictLRU();
        }
        lruList_.emplace_front(key);
        cache_[key] = Node{ std::move(value), lruList_.begin() };
        nodeTimestamps_[key] = Clock::now();
    }

    /**
     * @brief Insert or update a key-value pair (copy version).
     * @param key The key.
     * @param value The value (copy).
     */
    void Put(const K& key, const V& value)
    {
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            it->second.value = value;
            Touch(it);
            nodeTimestamps_[key] = Clock::now();
            return;
        }
        EvictExpired();
        if (cache_.size() >= config_.maxSize) {
            EvictLRU();
        }
        lruList_.emplace_front(key);
        cache_[key] = Node{ value, lruList_.begin() };
        nodeTimestamps_[key] = Clock::now();
    }

    /**
     * @brief Remove a key from the cache.
     * @return true if removed, false if key did not exist.
     */
    bool Remove(const K& key)
    {
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            return false;
        }
        lruList_.erase(it->second.listIt);
        cache_.erase(it);
        nodeTimestamps_.erase(key);
        return true;
    }

    /**
     * @brief Clear all entries from the cache.
     */
    void Clear()
    {
        lruList_.clear();
        cache_.clear();
        nodeTimestamps_.clear();
    }

    /**
     * @brief Check if the cache contains a key.
     * @return true if the key exists and is not expired, false otherwise.
     */
    bool Contains(const K& key)
    {
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            return false;
        }
        if (config_.enableTTL) {
            auto tsIt = nodeTimestamps_.find(key);
            if (tsIt != nodeTimestamps_.end()) {
                auto age = Clock::now() - tsIt->second;
                if (age > config_.ttl) {
                    Remove(key);
                    ++expireCount_;
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @brief Get the current number of entries in the cache.
     * @return The cache size.
     */
    size_t Size() const
    {
        return cache_.size();
    }

    /**
     * @brief Check if the cache is empty.
     * @return true if empty, false otherwise.
     */
    bool Empty() const
    {
        return cache_.empty();
    }

    /**
     * @brief Get cache statistics.
     * @return Stats struct containing hits, misses, evictions, and expires counts.
     */
    Stats GetStats() const
    {
        Stats s;
        s.hits = hitCount_;
        s.misses = missCount_;
        s.evictions = evictCount_;
        s.expires = expireCount_;
        return s;
    }

    /**
     * @brief Reset all statistics counters to zero.
     */
    void ResetStats()
    {
        hitCount_ = 0;
        missCount_ = 0;
        evictCount_ = 0;
        expireCount_ = 0;
    }

    /**
     * @brief Force eviction of all expired entries.
     * @return Number of entries evicted.
     */
    size_t EvictExpired()
    {
        if (!config_.enableTTL || nodeTimestamps_.empty()) {
            return 0;
        }
        auto now = Clock::now();
        auto threshold = now - config_.ttl;
        std::vector<K> expiredKeys;
        for (const auto& entry : nodeTimestamps_) {
            if (entry.second < threshold) {
                expiredKeys.push_back(entry.first);
            }
        }
        if (expiredKeys.empty()) {
            return 0;
        }
        size_t evictedCount = expiredKeys.size();
        for (const auto& key : expiredKeys) {
            Remove(key);
            ++expireCount_;
        }
        return evictedCount;
    }

    /**
     * @brief Get the current cache configuration.
     * @return The Config struct.
     */
    Config GetConfig() const
    {
        return config_;
    }

    /**
     * @brief Update cache configuration.
     * @param config The new configuration.
     */
    void UpdateConfig(const Config& config)
    {
        config_ = config;
        EvictExpired();
        while (cache_.size() > config_.maxSize) {
            EvictLRU();
        }
    }

    /**
     * @brief Get all keys currently in the cache.
     * @return Vector of keys.
     */
    std::vector<K> GetAllKeys()
    {
        EvictExpired();
        std::vector<K> keys;
        keys.reserve(cache_.size());
        for (const auto& entry : cache_) {
            keys.push_back(entry.first);
        }
        return keys;
    }

private:
    void Touch(typename std::unordered_map<K, Node>::iterator it)
    {
        lruList_.erase(it->second.listIt);
        lruList_.emplace_front(it->first);
        it->second.listIt = lruList_.begin();
    }

    void EvictLRU()
    {
        if (lruList_.empty()) {
            return;
        }
        auto oldest = lruList_.back();
        cache_.erase(oldest);
        nodeTimestamps_.erase(oldest);
        lruList_.pop_back();
        ++evictCount_;
    }

private:
    Config config_;

    std::list<K> lruList_;
    std::unordered_map<K, Node> cache_;
    std::unordered_map<K, TimePoint> nodeTimestamps_;

    size_t hitCount_ = 0;
    size_t missCount_ = 0;
    size_t evictCount_ = 0;
    size_t expireCount_ = 0;
};

}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_LRU_CACHE_H
