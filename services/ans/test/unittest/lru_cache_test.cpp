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

#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <vector>

#define private public
#define protected public
#include "utils/lru_cache.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::Notification;

namespace {

struct TestValue {
    int id;
    std::string name;

    TestValue() : id(0), name("") {}
    TestValue(int id, const std::string& name) : id(id), name(name) {}
    TestValue(int id, std::string&& name) : id(id), name(std::move(name)) {}

    bool operator==(const TestValue& other) const
    {
        return id == other.id && name == other.name;
    }
};
}

class LRUCacheTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: PutAndGet_Basic_00001
 * @tc.desc: Test basic put and get operations
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, PutAndGet_Basic_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    TestValue result;
    bool found = cache.Get("key1", result);

    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");
}

/**
 * @tc.name: Get_NotFound_00001
 * @tc.desc: Test get returns false for non-existent key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Get_NotFound_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    TestValue result;
    bool found = cache.Get("non_existent", result);

    EXPECT_FALSE(found);
}

/**
 * @tc.name: Put_UpdateExisting_00001
 * @tc.desc: Test updating existing key updates value
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Put_UpdateExisting_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key1", TestValue(2, "value2"));

    TestValue result;
    bool found = cache.Get("key1", result);

    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 2);
    EXPECT_EQ(result.name, "value2");
    EXPECT_EQ(cache.Size(), 1);
}

/**
 * @tc.name: Remove_Existing_00001
 * @tc.desc: Test removing existing key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Remove_Existing_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    EXPECT_EQ(cache.Size(), 1);

    bool removed = cache.Remove("key1");

    EXPECT_TRUE(removed);
    EXPECT_EQ(cache.Size(), 0);

    TestValue result;
    EXPECT_FALSE(cache.Get("key1", result));
}

/**
 * @tc.name: Remove_NonExisting_00001
 * @tc.desc: Test removing non-existing key returns false
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Remove_NonExisting_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;

    bool removed = cache.Remove("non_existent");

    EXPECT_FALSE(removed);
}

/**
 * @tc.name: Clear_00001
 * @tc.desc: Test clearing all entries
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Clear_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));
    EXPECT_EQ(cache.Size(), 3);

    cache.Clear();

    EXPECT_EQ(cache.Size(), 0);
    EXPECT_TRUE(cache.Empty());
}

/**
 * @tc.name: Contains_Existing_00001
 * @tc.desc: Test contains returns true for existing key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Contains_Existing_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    EXPECT_TRUE(cache.Contains("key1"));
}

/**
 * @tc.name: Contains_NonExisting_00001
 * @tc.desc: Test contains returns false for non-existing key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Contains_NonExisting_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;

    EXPECT_FALSE(cache.Contains("non_existent"));
}

/**
 * @tc.name: Size_Empty_00001
 * @tc.desc: Test size is zero for empty cache
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Size_Empty_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;

    EXPECT_EQ(cache.Size(), 0);
    EXPECT_TRUE(cache.Empty());
}

/**
 * @tc.name: Size_MultipleEntries_00001
 * @tc.desc: Test size with multiple entries
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Size_MultipleEntries_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));

    EXPECT_EQ(cache.Size(), 3);
    EXPECT_FALSE(cache.Empty());
}

/**
 * @tc.name: LRU_Eviction_Oldest_00001
 * @tc.desc: Test LRU eviction removes oldest accessed item
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, LRU_Eviction_Oldest_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 3;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));

    // Access key1 to make it recently used
    TestValue temp;
    cache.Get("key1", temp);

    // Add new entry, should evict key2 (least recently used)
    cache.Put("key4", TestValue(4, "value4"));

    EXPECT_EQ(cache.Size(), 3);
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key3"));
    EXPECT_TRUE(cache.Contains("key4"));
    EXPECT_FALSE(cache.Contains("key2"));
}

/**
 * @tc.name: LRU_Eviction_FullCapacity_00001
 * @tc.desc: Test cache evicts when at max capacity
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, LRU_Eviction_FullCapacity_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 2;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    EXPECT_EQ(cache.Size(), 2);

    // Adding third item should trigger eviction
    cache.Put("key3", TestValue(3, "value3"));

    EXPECT_EQ(cache.Size(), 2);
}

/**
 * @tc.name: Stats_HitAndMiss_00001
 * @tc.desc: Test cache hit and miss statistics
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Stats_HitAndMiss_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Hit
    TestValue result;
    cache.Get("key1", result);

    // Miss
    cache.Get("non_existent", result);

    auto stats = cache.GetStats();
    EXPECT_EQ(stats.hits, 1);
    EXPECT_EQ(stats.misses, 1);
    EXPECT_DOUBLE_EQ(stats.HitRate(), 0.5);
}

/**
 * @tc.name: Stats_Eviction_00001
 * @tc.desc: Test eviction statistics
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Stats_Eviction_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 2;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));  // Should evict key1

    auto stats = cache.GetStats();
    EXPECT_EQ(stats.evictions, 1);
}

/**
 * @tc.name: ResetStats_00001
 * @tc.desc: Test resetting statistics
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, ResetStats_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    TestValue result;
    cache.Get("key1", result);
    cache.Get("non_existent", result);

    auto stats = cache.GetStats();
    EXPECT_EQ(stats.hits, 1);
    EXPECT_EQ(stats.misses, 1);

    cache.ResetStats();

    stats = cache.GetStats();
    EXPECT_EQ(stats.hits, 0);
    EXPECT_EQ(stats.misses, 0);
}

/**
 * @tc.name: GetAllKeys_00001
 * @tc.desc: Test getting all keys in cache
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, GetAllKeys_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));

    auto keys = cache.GetAllKeys();

    EXPECT_EQ(keys.size(), 3);
    EXPECT_TRUE(std::find(keys.begin(), keys.end(), "key1") != keys.end());
    EXPECT_TRUE(std::find(keys.begin(), keys.end(), "key2") != keys.end());
    EXPECT_TRUE(std::find(keys.begin(), keys.end(), "key3") != keys.end());
}

/**
 * @tc.name: UpdateConfig_ChangeMaxSize_00001
 * @tc.desc: Test updating cache config changes max size
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, UpdateConfig_ChangeMaxSize_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 5;
    LRUCache<std::string, TestValue> cache(config);

    EXPECT_EQ(cache.GetConfig().maxSize, 5);

    config.maxSize = 10;
    cache.UpdateConfig(config);

    EXPECT_EQ(cache.GetConfig().maxSize, 10);
}

/**
 * @tc.name: UpdateConfig_EnforceNewLimit_00001
 * @tc.desc: Test updating config enforces new size limit
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, UpdateConfig_EnforceNewLimit_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 5;
    LRUCache<std::string, TestValue> cache(config);

    // Fill cache
    for (int i = 0; i < 5; ++i) {
        cache.Put("key" + std::to_string(i), TestValue(i, "value" + std::to_string(i)));
    }
    EXPECT_EQ(cache.Size(), 5);

    // Reduce max size - should evict entries
    config.maxSize = 2;
    cache.UpdateConfig(config);

    EXPECT_EQ(cache.Size(), 2);
}

/**
 * @tc.name: Peek_DoesNotUpdateAccessTime_00001
 * @tc.desc: Test peek does not update access time
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Peek_DoesNotUpdateAccessTime_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 2;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    // Peek at key1 (should not update its access time)
    TestValue result;
    cache.Peek("key1", result);
    EXPECT_TRUE(result.id == 1);

    // Add new entry - key1 should be evicted since peek didn't update its access time
    cache.Put("key3", TestValue(3, "value3"));

    EXPECT_EQ(cache.Size(), 2);
    EXPECT_TRUE(cache.Contains("key2"));
    EXPECT_TRUE(cache.Contains("key3"));
    // key1 should be evicted because Peek doesn't refresh its LRU position
    EXPECT_FALSE(cache.Contains("key1"));
}

/**
 * @tc.name: MoveSemantics_PutRvalue_00001
 * @tc.desc: Test put with rvalue reference
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, MoveSemantics_PutRvalue_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;

    TestValue value(1, "test");
    cache.Put("key1", std::move(value));

    TestValue result;
    bool found = cache.Get("key1", result);

    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "test");
}

/**
 * @tc.name: Peek_ExpiredAutoRemove_00001
 * @tc.desc: Test peeking expired entry returns value, then EvictExpired removes it
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Peek_ExpiredAutoRemove_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Manually expire the entry by setting old timestamp
    cache.nodeTimestamps_["key1"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: Peek no longer checks TTL, returns expired value
    TestValue result;
    bool found = cache.Peek("key1", result);
    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");
    EXPECT_EQ(cache.Size(), 1);

    // Actively evict expired entries, then Peek returns false
    size_t evicted = cache.EvictExpired();
    EXPECT_EQ(evicted, 1);
    EXPECT_FALSE(cache.Peek("key1", result));
    EXPECT_EQ(cache.Size(), 0);
}

/**
 * @tc.name: Contains_ExpiredAutoRemove_00001
 * @tc.desc: Test contains on expired entry returns true, then EvictExpired removes it
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Contains_ExpiredAutoRemove_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Manually expire the entry by setting old timestamp
    cache.nodeTimestamps_["key1"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: Contains no longer checks TTL, returns true for expired entry
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_EQ(cache.Size(), 1);

    // Actively evict expired entries, then Contains returns false
    size_t evicted = cache.EvictExpired();
    EXPECT_EQ(evicted, 1);
    EXPECT_FALSE(cache.Contains("key1"));
    EXPECT_EQ(cache.Size(), 0);
}

/**
 * @tc.name: Put_FullCache_EvictExpiredFirst_00001
 * @tc.desc: Test that EvictExpired clears expired entries before Put adds new ones
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Put_FullCache_EvictExpiredFirst_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 3;
    config.enableTTL = true;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));
    EXPECT_EQ(cache.Size(), 3);

    // Expire key2 only
    cache.nodeTimestamps_["key2"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: Put no longer evicts expired entries. Actively call EvictExpired first.
    size_t evicted = cache.EvictExpired();
    EXPECT_EQ(evicted, 1);
    EXPECT_EQ(cache.Size(), 2);
    EXPECT_FALSE(cache.Contains("key2"));

    // Now Put can add new entry without LRU eviction
    cache.Put("key4", TestValue(4, "value4"));

    EXPECT_EQ(cache.Size(), 3);
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key3"));
    EXPECT_TRUE(cache.Contains("key4"));
}

/**
 * @tc.name: Put_FullCache_ExpiredThenLRU_00001
 * @tc.desc: Test that when cache is full after evicting expired, LRU eviction follows
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Put_FullCache_ExpiredThenLRU_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 3;
    config.enableTTL = true;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));
    EXPECT_EQ(cache.Size(), 3);

    // No expired entries, must use LRU eviction
    cache.Put("key4", TestValue(4, "value4"));

    EXPECT_EQ(cache.Size(), 3);
    EXPECT_FALSE(cache.Contains("key1")); // key1 was LRU, evicted
    EXPECT_TRUE(cache.Contains("key2"));
    EXPECT_TRUE(cache.Contains("key3"));
    EXPECT_TRUE(cache.Contains("key4"));
}

/**
 * @tc.name: GetAllKeys_FiltersExpired_00001
 * @tc.desc: Test GetAllKeys returns all entries, then EvictExpired filters out expired ones
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, GetAllKeys_FiltersExpired_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    // Expire key2
    cache.nodeTimestamps_["key2"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: GetAllKeys no longer filters expired entries, returns all keys
    auto keys = cache.GetAllKeys();
    EXPECT_EQ(keys.size(), 2);
    EXPECT_EQ(cache.Size(), 2);

    // Actively evict expired entries, then GetAllKeys returns only non-expired keys
    size_t evicted = cache.EvictExpired();
    EXPECT_EQ(evicted, 1);
    keys = cache.GetAllKeys();
    EXPECT_EQ(keys.size(), 1);
    EXPECT_EQ(keys[0], "key1");
    EXPECT_EQ(cache.Size(), 1);
}

/**
 * @tc.name: Put_FullCache_AllExpired_NoLRU_00001
 * @tc.desc: Test that EvictExpired clears all expired entries, then Put adds without LRU
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Put_FullCache_AllExpired_NoLRU_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 2;
    config.enableTTL = true;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    cache.nodeTimestamps_["key1"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);
    cache.nodeTimestamps_["key2"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: Put no longer evicts expired entries. Actively call EvictExpired first.
    size_t evicted = cache.EvictExpired();
    EXPECT_EQ(evicted, 2);
    EXPECT_EQ(cache.Size(), 0);
    EXPECT_FALSE(cache.Contains("key1"));
    EXPECT_FALSE(cache.Contains("key2"));

    // Now Put can add new entry without LRU eviction
    cache.Put("key3", TestValue(3, "value3"));

    EXPECT_EQ(cache.Size(), 1);
    EXPECT_TRUE(cache.Contains("key3"));
}


/**
 * @tc.name: EvictExpired_NoExpired_ReturnsZero_00001
 * @tc.desc: Test EvictExpired returns 0 when no entries are expired
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, EvictExpired_NoExpired_ReturnsZero_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    size_t evicted = cache.EvictExpired();

    EXPECT_EQ(evicted, 0);
    EXPECT_EQ(cache.Size(), 2);
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key2"));
}

/**
 * @tc.name: UpdateConfig_ReduceSize_EvictsExpiredFirst_00001
 * @tc.desc: Test UpdateConfig reduces maxSize, evicts expired before LRU
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, UpdateConfig_ReduceSize_EvictsExpiredFirst_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 5;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));
    cache.Put("key4", TestValue(4, "value4"));
    cache.Put("key5", TestValue(5, "value5"));
    EXPECT_EQ(cache.Size(), 5);

    // Expire key4 and key5
    cache.nodeTimestamps_["key4"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);
    cache.nodeTimestamps_["key5"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // Reduce maxSize to 3: 2 expired evicted first, remaining 3 equals new limit, no LRU
    config.maxSize = 3;
    cache.UpdateConfig(config);

    EXPECT_EQ(cache.Size(), 3);
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key2"));
    EXPECT_TRUE(cache.Contains("key3"));
    EXPECT_FALSE(cache.Contains("key4"));
    EXPECT_FALSE(cache.Contains("key5"));
}

/**
 * @tc.name: UpdateConfig_ReduceSize_ExpiredThenLRU_00001
 * @tc.desc: Test UpdateConfig reduces maxSize, expired evicted then LRU follows
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, UpdateConfig_ReduceSize_ExpiredThenLRU_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 5;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));
    cache.Put("key4", TestValue(4, "value4"));
    cache.Put("key5", TestValue(5, "value5"));
    EXPECT_EQ(cache.Size(), 5);

    // Expire key4 only (1 expired)
    cache.nodeTimestamps_["key4"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // Reduce maxSize to 3: 1 expired evicted + 1 LRU eviction (key1 is LRU)
    config.maxSize = 3;
    cache.UpdateConfig(config);

    EXPECT_EQ(cache.Size(), 3);
    EXPECT_FALSE(cache.Contains("key1")); // LRU evicted
    EXPECT_TRUE(cache.Contains("key2"));
    EXPECT_TRUE(cache.Contains("key3"));
    EXPECT_FALSE(cache.Contains("key4")); // expired
    EXPECT_TRUE(cache.Contains("key5"));
}

/**
 * @tc.name: CopyConstructor_00001
 * @tc.desc: Test copy constructor creates independent cache with same data
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, CopyConstructor_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));

    LRUCache<std::string, TestValue> copiedCache(cache);

    EXPECT_EQ(copiedCache.Size(), 3);
    EXPECT_TRUE(copiedCache.Contains("key1"));
    EXPECT_TRUE(copiedCache.Contains("key2"));
    EXPECT_TRUE(copiedCache.Contains("key3"));

    auto originalStats = cache.GetStats();
    auto copiedStats = copiedCache.GetStats();
    EXPECT_EQ(copiedStats.hits, 0);
    EXPECT_EQ(copiedStats.misses, 0);
    EXPECT_EQ(originalStats.hits, copiedStats.hits);
    EXPECT_EQ(originalStats.misses, copiedStats.misses);

    TestValue result;
    EXPECT_TRUE(copiedCache.Get("key1", result));
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");

    copiedCache.Put("key4", TestValue(4, "value4"));
    EXPECT_EQ(copiedCache.Size(), 4);
    EXPECT_EQ(cache.Size(), 3);
    EXPECT_FALSE(cache.Contains("key4"));
}

/**
 * @tc.name: CopyAssignment_00001
 * @tc.desc: Test copy assignment operator copies all data correctly
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, CopyAssignment_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache1;
    cache1.Put("key1", TestValue(1, "value1"));
    cache1.Put("key2", TestValue(2, "value2"));

    LRUCache<std::string, TestValue> cache2;
    cache2.Put("key3", TestValue(3, "value3"));

    cache2 = cache1;

    EXPECT_EQ(cache2.Size(), 2);
    EXPECT_TRUE(cache2.Contains("key1"));
    EXPECT_TRUE(cache2.Contains("key2"));
    EXPECT_FALSE(cache2.Contains("key3"));

    TestValue result;
    EXPECT_TRUE(cache2.Get("key1", result));
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");

    cache2.Put("key4", TestValue(4, "value4"));
    EXPECT_EQ(cache2.Size(), 3);
    EXPECT_EQ(cache1.Size(), 2);
}

/**
 * @tc.name: CopyAssignment_SelfAssignment_00001
 * @tc.desc: Test self-assignment does not corrupt cache
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, CopyAssignment_SelfAssignment_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    LRUCache<std::string, TestValue>& cacheRef = cache;
    cache = cacheRef;

    EXPECT_EQ(cache.Size(), 2);
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key2"));

    TestValue result;
    EXPECT_TRUE(cache.Get("key1", result));
    EXPECT_EQ(result.id, 1);
}

/**
 * @tc.name: Get_ExpiredEntry_00001
 * @tc.desc: Test Get returns expired entry, then EvictExpired removes it
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Get_ExpiredEntry_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Inject expired timestamp
    cache.nodeTimestamps_["key1"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: Get no longer checks TTL, returns expired value
    TestValue result;
    bool found = cache.Get("key1", result);
    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");
    EXPECT_EQ(cache.Size(), 1);

    // Actively evict expired entries, then Get returns false
    size_t evicted = cache.EvictExpired();
    EXPECT_EQ(evicted, 1);
    EXPECT_FALSE(cache.Get("key1", result));
    EXPECT_EQ(cache.Size(), 0);
}

/**
 * @tc.name: Get_MissingTimestamp_00001
 * @tc.desc: Test Get returns entry even without timestamp (no TTL check)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Get_MissingTimestamp_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Remove timestamp to simulate corrupted state
    cache.nodeTimestamps_.erase("key1");

    // After refactoring: Get no longer checks timestamp, returns entry value
    TestValue result;
    bool found = cache.Get("key1", result);
    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");
    EXPECT_EQ(cache.Size(), 1);
}

/**
 * @tc.name: Peek_NonExisting_00001
 * @tc.desc: Test Peek returns false for non-existent key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Peek_NonExisting_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    TestValue result;
    bool found = cache.Peek("non_existent", result);

    EXPECT_FALSE(found);
}

/**
 * @tc.name: Peek_MissingTimestamp_00001
 * @tc.desc: Test Peek returns entry even without timestamp (no TTL check)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Peek_MissingTimestamp_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Remove timestamp to simulate corrupted state
    cache.nodeTimestamps_.erase("key1");

    // After refactoring: Peek no longer checks timestamp, returns entry value
    TestValue result;
    bool found = cache.Peek("key1", result);
    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");
    EXPECT_EQ(cache.Size(), 1);
}

/**
 * @tc.name: Empty_True_00001
 * @tc.desc: Test Empty returns true for cache with no entries
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Empty_True_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;

    EXPECT_TRUE(cache.Empty());
    EXPECT_EQ(cache.Size(), 0);
}

/**
 * @tc.name: Empty_False_00001
 * @tc.desc: Test Empty returns false for cache with entries
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Empty_False_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    EXPECT_FALSE(cache.Empty());
    EXPECT_EQ(cache.Size(), 1);
}

/**
 * @tc.name: EvictExpired_MultipleExpired_00001
 * @tc.desc: Test EvictExpired removes all expired entries and returns count
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, EvictExpired_MultipleExpired_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));
    cache.Put("key4", TestValue(4, "value4"));

    cache.nodeTimestamps_["key1"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);
    cache.nodeTimestamps_["key2"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    size_t evicted = cache.EvictExpired();

    EXPECT_EQ(evicted, 2);
    EXPECT_EQ(cache.Size(), 2);
    EXPECT_FALSE(cache.Contains("key1"));
    EXPECT_FALSE(cache.Contains("key2"));
    EXPECT_TRUE(cache.Contains("key3"));
    EXPECT_TRUE(cache.Contains("key4"));

    auto stats = cache.GetStats();
    EXPECT_EQ(stats.expires, 2);
}

/**
 * @tc.name: EvictExpired_DisabledTTL_00001
 * @tc.desc: Test EvictExpired returns 0 when TTL is disabled
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, EvictExpired_DisabledTTL_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.enableTTL = false;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    size_t evicted = cache.EvictExpired();

    EXPECT_EQ(evicted, 0);
    EXPECT_EQ(cache.Size(), 2);
}

/**
 * @tc.name: TTLDisabled_00001
 * @tc.desc: Test cache operations when TTL is disabled
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, TTLDisabled_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.enableTTL = false;
    config.maxSize = 3;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));
    cache.Put("key3", TestValue(3, "value3"));

    TestValue result;
    EXPECT_TRUE(cache.Get("key1", result));
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Peek("key2", result));
    EXPECT_EQ(cache.nodeTimestamps_.size(), 3);

    cache.Put("key4", TestValue(4, "value4"));
    EXPECT_EQ(cache.Size(), 3);
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_FALSE(cache.Contains("key2"));

    auto stats = cache.GetStats();
    EXPECT_EQ(stats.expires, 0);
}

/**
 * @tc.name: Stats_HitRate_EmptyCache_00001
 * @tc.desc: Test HitRate returns 0 when no hits or misses
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Stats_HitRate_EmptyCache_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;

    auto stats = cache.GetStats();
    EXPECT_EQ(stats.hits, 0);
    EXPECT_EQ(stats.misses, 0);
    EXPECT_DOUBLE_EQ(stats.HitRate(), 0.0);
}

/**
 * @tc.name: Stats_HitRate_AllHits_00001
 * @tc.desc: Test HitRate returns 1.0 when all operations are hits
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Stats_HitRate_AllHits_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    TestValue result;
    cache.Get("key1", result);
    cache.Get("key2", result);

    auto stats = cache.GetStats();
    EXPECT_EQ(stats.hits, 2);
    EXPECT_EQ(stats.misses, 0);
    EXPECT_DOUBLE_EQ(stats.HitRate(), 1.0);
}

/**
 * @tc.name: GetConfig_DefaultValues_00001
 * @tc.desc: Test GetConfig returns default configuration values
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, GetConfig_DefaultValues_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;

    auto config = cache.GetConfig();

    EXPECT_EQ(config.maxSize, 0);
    EXPECT_EQ(config.ttl, std::chrono::minutes(5));
    EXPECT_TRUE(config.enableTTL);
}

/**
 * @tc.name: Put_MaxSizeZero_NoCapacityLimit_00001
 * @tc.desc: Test that maxSize=0 means no capacity limit, entries are not evicted by size
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Put_MaxSizeZero_NoCapacityLimit_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 0;  // No capacity limit
    config.enableTTL = false;  // Disable TTL so entries persist
    LRUCache<std::string, TestValue> cache(config);

    // Insert more than the old default (100) entries
    for (size_t i = 0; i < 200; i++) {
        cache.Put("key" + std::to_string(i), TestValue(i, "value" + std::to_string(i)));
    }

    // All 200 entries should still be in cache (no capacity eviction)
    EXPECT_EQ(cache.Size(), 200);
    EXPECT_EQ(cache.GetStats().evictions, 0);

    // Verify all entries are accessible
    for (size_t i = 0; i < 200; i++) {
        TestValue val;
        EXPECT_TRUE(cache.Get("key" + std::to_string(i), val));
        EXPECT_EQ(val.id, i);
    }
}

/**
 * @tc.name: UpdateConfig_MaxSizeZero_NoEviction_00001
 * @tc.desc: Test that UpdateConfig with maxSize=0 does not evict entries
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, UpdateConfig_MaxSizeZero_NoEviction_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 5;
    config.enableTTL = false;
    LRUCache<std::string, TestValue> cache(config);

    for (size_t i = 0; i < 5; i++) {
        cache.Put("key" + std::to_string(i), TestValue(i, "value" + std::to_string(i)));
    }
    EXPECT_EQ(cache.Size(), 5);

    // Update to maxSize=0 (no limit) — should not evict anything
    config.maxSize = 0;
    cache.UpdateConfig(config);

    EXPECT_EQ(cache.Size(), 5);
    EXPECT_EQ(cache.GetStats().evictions, 0);

    // Can now add more entries beyond old limit
    for (size_t i = 5; i < 20; i++) {
        cache.Put("key" + std::to_string(i), TestValue(i, "value" + std::to_string(i)));
    }
    EXPECT_EQ(cache.Size(), 20);
}

/**
 * @tc.name: Contains_MissingTimestamp_00001
 * @tc.desc: Test Contains returns true even without timestamp (no TTL check)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Contains_MissingTimestamp_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Remove timestamp to simulate corrupted state
    cache.nodeTimestamps_.erase("key1");

    // After refactoring: Contains no longer checks timestamp, returns true
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_EQ(cache.Size(), 1);
}

/**
 * @tc.name: Put_CopyVersion_00001
 * @tc.desc: Test Put with copy version (const ref) works correctly
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Put_CopyVersion_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;

    TestValue value(1, "value1");
    cache.Put("key1", value);

    TestValue result;
    bool found = cache.Get("key1", result);

    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");
    EXPECT_EQ(value.id, 1);
}

/**
 * @tc.name: Put_UpdateExisting_CopyVersion_00001
 * @tc.desc: Test Put with copy version updates existing key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Put_UpdateExisting_CopyVersion_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    TestValue newValue(2, "newValue");
    cache.Put("key1", newValue);

    TestValue result;
    bool found = cache.Get("key1", result);

    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 2);
    EXPECT_EQ(result.name, "newValue");
    EXPECT_EQ(cache.Size(), 1);
}

/**
 * @tc.name: RemoveInternal_ThroughPeek_00001
 * @tc.desc: Test Peek does not trigger RemoveInternal, EvictExpired triggers it
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, RemoveInternal_ThroughPeek_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    // Expire key1
    cache.nodeTimestamps_["key1"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: Peek does not trigger RemoveInternal, expired entry remains
    TestValue result;
    cache.Peek("key1", result);
    EXPECT_EQ(cache.Size(), 2);
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key2"));
    EXPECT_EQ(cache.lruList_.size(), 2);

    // Actively evict expired entries triggers RemoveInternal
    size_t evicted = cache.EvictExpired();
    EXPECT_EQ(evicted, 1);
    EXPECT_EQ(cache.Size(), 1);
    EXPECT_FALSE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key2"));
    EXPECT_EQ(cache.lruList_.size(), 1);
}

/**
 * @tc.name: EvictExpired_DirectCall_00001
 * @tc.desc: Test direct EvictExpired call removes expired entries from full cache
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, EvictExpired_DirectCall_00001, Function | SmallTest | Level1)
{
    typename LRUCache<std::string, TestValue>::Config config;
    config.maxSize = 2;
    config.enableTTL = true;
    LRUCache<std::string, TestValue> cache(config);

    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    // Expire key1
    cache.nodeTimestamps_["key1"] = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: Get does not trigger cleanup, expired entry remains
    TestValue result;
    cache.Get("key2", result);
    EXPECT_EQ(cache.Size(), 2);
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key2"));

    // Directly call EvictExpired to clean up
    size_t evicted = cache.EvictExpired();
    EXPECT_EQ(evicted, 1);
    EXPECT_EQ(cache.Size(), 1);
    EXPECT_FALSE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key2"));
}

/**
 * @tc.name: GetAllKeys_EmptyCache_00001
 * @tc.desc: Test GetAllKeys on empty cache returns empty vector
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, GetAllKeys_EmptyCache_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;

    auto keys = cache.GetAllKeys();

    EXPECT_EQ(keys.size(), 0);
}

/**
 * @tc.name: Clear_ResetsTimestamps_00001
 * @tc.desc: Test Clear removes all timestamps
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Clear_ResetsTimestamps_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    EXPECT_EQ(cache.nodeTimestamps_.size(), 2);

    cache.Clear();

    EXPECT_EQ(cache.nodeTimestamps_.size(), 0);
    auto defaultTimePoint = LRUCache<std::string, TestValue>::TimePoint();
    EXPECT_EQ(cache.lastEvictionTime_, defaultTimePoint);
}

/**
 * @tc.name: Get_DoesNotCheckTTL_00001
 * @tc.desc: Test Get returns expired entry without TTL check (no passive eviction)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Get_DoesNotCheckTTL_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Inject expired timestamp
    cache.nodeTimestamps_["key1"] =
        LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: Get does not check TTL, returns expired value
    TestValue result;
    bool found = cache.Get("key1", result);
    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");

    // Expired entry is not evicted by Get (no passive TTL check)
    EXPECT_EQ(cache.Size(), 1);
    EXPECT_TRUE(cache.Contains("key1"));
}

/**
 * @tc.name: Put_DoesNotEvictExpired_00001
 * @tc.desc: Test Put does not trigger passive eviction of expired entries
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Put_DoesNotEvictExpired_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Inject expired timestamp on key1
    cache.nodeTimestamps_["key1"] =
        LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // Put a new entry; should not trigger passive eviction of expired key1
    cache.Put("key2", TestValue(2, "value2"));

    // Both expired and non-expired entries remain in cache (no passive eviction)
    EXPECT_EQ(cache.Size(), 2);
    EXPECT_TRUE(cache.Contains("key1"));
    EXPECT_TRUE(cache.Contains("key2"));
}

/**
 * @tc.name: Contains_DoesNotCheckTTL_00001
 * @tc.desc: Test Contains returns true for expired entry without TTL check
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Contains_DoesNotCheckTTL_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Inject expired timestamp
    cache.nodeTimestamps_["key1"] =
        LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: Contains does not check TTL, returns true for expired entry
    EXPECT_TRUE(cache.Contains("key1"));

    // Size remains unchanged (no passive eviction)
    EXPECT_EQ(cache.Size(), 1);
}

/**
 * @tc.name: GetAllKeys_DoesNotFilterExpired_00001
 * @tc.desc: Test GetAllKeys returns all keys including expired ones (no TTL filtering)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, GetAllKeys_DoesNotFilterExpired_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));
    cache.Put("key2", TestValue(2, "value2"));

    // Expire key1
    cache.nodeTimestamps_["key1"] =
        LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);

    // After refactoring: GetAllKeys does not filter expired entries, returns all keys
    auto keys = cache.GetAllKeys();
    EXPECT_EQ(keys.size(), 2);
    EXPECT_TRUE(std::find(keys.begin(), keys.end(), "key1") != keys.end());
    EXPECT_TRUE(std::find(keys.begin(), keys.end(), "key2") != keys.end());

    // Cache size remains unchanged (no passive eviction)
    EXPECT_EQ(cache.Size(), 2);
}

/**
 * @tc.name: Peek_DoesNotCheckTTL_00001
 * @tc.desc: Test Peek returns expired entry without TTL check (timestamp not refreshed)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Peek_DoesNotCheckTTL_00001, Function | SmallTest | Level1)
{
    LRUCache<std::string, TestValue> cache;
    cache.Put("key1", TestValue(1, "value1"));

    // Inject expired timestamp
    auto expiredTime = LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);
    cache.nodeTimestamps_["key1"] = expiredTime;

    // After refactoring: Peek does not check TTL, returns expired value
    TestValue result;
    bool found = cache.Peek("key1", result);
    EXPECT_TRUE(found);
    EXPECT_EQ(result.id, 1);
    EXPECT_EQ(result.name, "value1");

    // Timestamp is not refreshed by Peek (Peek does not update access metadata)
    EXPECT_EQ(cache.nodeTimestamps_["key1"], expiredTime);

    // Size remains unchanged (no passive eviction)
    EXPECT_EQ(cache.Size(), 1);
}

/**
 * @tc.name: Get_Performance_NoTTLCheck_00001
 * @tc.desc: Test Get hot path performance: 250 lookups on non-expired entries < 1ms (no TTL check)
 * @tc.type: PERF
 * @tc.require: issue
 */
HWTEST_F(LRUCacheTest, Get_Performance_NoTTLCheck_00001, Performance | MediumTest | Level2)
{
    LRUCache<std::string, TestValue> cache;
    // Fill cache with 500 entries
    for (int i = 0; i < 500; i++) {
        cache.Put("key" + std::to_string(i), TestValue(i, "value"));
    }
    // Inject expired timestamps for first 250 entries
    for (int i = 0; i < 250; i++) {
        cache.nodeTimestamps_["key" + std::to_string(i)] =
            LRUCache<std::string, TestValue>::Clock::now() - std::chrono::minutes(10);
    }

    // Measure Get performance on non-expired entries (key250 ~ key499)
    auto start = std::chrono::steady_clock::now();
    TestValue out;
    for (int i = 250; i < 500; i++) {
        cache.Get("key" + std::to_string(i), out);
    }
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // After refactoring: Get does not perform TTL checks, 250 lookups should be < 1ms
    EXPECT_LT(duration.count(), 1000);
}
