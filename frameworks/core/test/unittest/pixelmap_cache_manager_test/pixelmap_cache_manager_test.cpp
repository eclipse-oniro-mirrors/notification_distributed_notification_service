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

#define private public
#define protected public
#include "pixelmap_cache_manager.h"
#undef private
#undef protected

#include "pixel_map.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class PixelMapCacheManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

std::shared_ptr<Media::PixelMap> CreateTestPixelMap(int32_t width = 100, int32_t height = 100)
{
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.srcPixelFormat = Media::PixelFormat::BGRA_8888;
    
    uint32_t bufferSize = width * height * 4;
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(bufferSize);
    
    auto pixelMap = Media::PixelMap::Create(
        reinterpret_cast<uint32_t*>(buffer.get()),
        bufferSize / 4, 0, width, opts, true);
    
    return pixelMap;
}

/**
 * @tc.name: GetCachedPixelMap_CacheNotExist_00001
 * @tc.desc: Test GetCachedPixelMap when cache does not exist, should return nullptr
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, GetCachedPixelMap_CacheNotExist_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto result = cacheManager->GetCachedPixelMap("test_request", "test_cache");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GetCachedPixelMap_CacheHit_00001
 * @tc.desc: Test GetCachedPixelMap when cache exists, should return pixelMap and record reference
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, GetCachedPixelMap_CacheHit_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto pixelMap = CreateTestPixelMap();
    
    cacheManager->CachePixelMap("test_request", "test_cache", pixelMap);
    auto result = cacheManager->GetCachedPixelMap("test_request", "test_cache");
    
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result, pixelMap);
    
    cacheManager->RemoveCache("test_request");
}

/**
 * @tc.name: GetCachedPixelMap_MultipleRequests_00001
 * @tc.desc: Test GetCachedPixelMap when multiple requests access same cacheKey
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, GetCachedPixelMap_MultipleRequests_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto pixelMap = CreateTestPixelMap();
    
    cacheManager->CachePixelMap("request1", "shared_cache", pixelMap);
    auto result1 = cacheManager->GetCachedPixelMap("request2", "shared_cache");
    
    EXPECT_NE(result1, nullptr);
    EXPECT_EQ(result1, pixelMap);
    EXPECT_EQ(cacheManager->requestToCacheKeys_["request2"].count("shared_cache"), 1u);
    
    cacheManager->RemoveCache("request1");
    cacheManager->RemoveCache("request2");
}

/**
 * @tc.name: CachePixelMap_NullInput_00001
 * @tc.desc: Test CachePixelMap with nullptr pixelMap, should skip caching
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, CachePixelMap_NullInput_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    cacheManager->CachePixelMap("test_request", "test_cache", nullptr);
    
    EXPECT_EQ(cacheManager->globalCache_.find("test_cache"), cacheManager->globalCache_.end());
}

/**
 * @tc.name: CachePixelMap_FirstTime_00001
 * @tc.desc: Test CachePixelMap first time store, should create new cache entry
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, CachePixelMap_FirstTime_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto pixelMap = CreateTestPixelMap();
    
    cacheManager->CachePixelMap("test_request", "test_cache", pixelMap);
    
    EXPECT_NE(cacheManager->globalCache_.find("test_cache"), cacheManager->globalCache_.end());
    EXPECT_EQ(cacheManager->globalCache_["test_cache"], pixelMap);
    EXPECT_EQ(cacheManager->requestToCacheKeys_["test_request"].count("test_cache"), 1u);
    
    cacheManager->RemoveCache("test_request");
}

/**
 * @tc.name: CachePixelMap_SharedReference_00001
 * @tc.desc: Test CachePixelMap when multiple requests share same cacheKey
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, CachePixelMap_SharedReference_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto pixelMap = CreateTestPixelMap();
    
    cacheManager->CachePixelMap("request1", "shared_cache", pixelMap);
    cacheManager->CachePixelMap("request2", "shared_cache", pixelMap);
    cacheManager->CachePixelMap("request3", "shared_cache", pixelMap);
    
    EXPECT_EQ(cacheManager->globalCache_.size(), 1u);
    EXPECT_EQ(cacheManager->requestToCacheKeys_["request1"].count("shared_cache"), 1u);
    EXPECT_EQ(cacheManager->requestToCacheKeys_["request2"].count("shared_cache"), 1u);
    EXPECT_EQ(cacheManager->requestToCacheKeys_["request3"].count("shared_cache"), 1u);
    
    cacheManager->RemoveCache("request1");
    cacheManager->RemoveCache("request2");
    cacheManager->RemoveCache("request3");
}

/**
 * @tc.name: RemoveCache_NoOtherRefs_00001
 * @tc.desc: Test RemoveCache when cacheKey has no other references, should delete pixelMap
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, RemoveCache_NoOtherRefs_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto pixelMap = CreateTestPixelMap();
    
    cacheManager->CachePixelMap("test_request", "test_cache", pixelMap);
    EXPECT_NE(cacheManager->globalCache_.find("test_cache"), cacheManager->globalCache_.end());
    
    cacheManager->RemoveCache("test_request");
    EXPECT_EQ(cacheManager->globalCache_.find("test_cache"), cacheManager->globalCache_.end());
    EXPECT_EQ(cacheManager->requestToCacheKeys_.find("test_request"), cacheManager->requestToCacheKeys_.end());
}

/**
 * @tc.name: RemoveCache_HasOtherRefs_00001
 * @tc.desc: Test RemoveCache when cacheKey has other references, should keep pixelMap
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, RemoveCache_HasOtherRefs_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto pixelMap = CreateTestPixelMap();
    
    cacheManager->CachePixelMap("request1", "shared_cache", pixelMap);
    cacheManager->CachePixelMap("request2", "shared_cache", pixelMap);
    
    cacheManager->RemoveCache("request1");
    
    EXPECT_NE(cacheManager->globalCache_.find("shared_cache"), cacheManager->globalCache_.end());
    EXPECT_EQ(cacheManager->requestToCacheKeys_.find("request1"), cacheManager->requestToCacheKeys_.end());
    EXPECT_NE(cacheManager->requestToCacheKeys_.find("request2"), cacheManager->requestToCacheKeys_.end());
    
    cacheManager->RemoveCache("request2");
    EXPECT_EQ(cacheManager->globalCache_.find("shared_cache"), cacheManager->globalCache_.end());
}

/**
 * @tc.name: RemoveCache_MultipleCacheKeys_00001
 * @tc.desc: Test RemoveCache when one requestKey has multiple cacheKeys
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, RemoveCache_MultipleCacheKeys_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto pixelMap1 = CreateTestPixelMap();
    auto pixelMap2 = CreateTestPixelMap();
    
    cacheManager->CachePixelMap("test_request", "cache1", pixelMap1);
    cacheManager->CachePixelMap("test_request", "cache2", pixelMap2);
    
    EXPECT_EQ(cacheManager->requestToCacheKeys_["test_request"].size(), 2u);
    EXPECT_EQ(cacheManager->globalCache_.size(), 2u);
    
    cacheManager->RemoveCache("test_request");
    
    EXPECT_EQ(cacheManager->requestToCacheKeys_.find("test_request"), cacheManager->requestToCacheKeys_.end());
    EXPECT_EQ(cacheManager->globalCache_.size(), 0u);
}

/**
 * @tc.name: RemoveCache_MixedReferences_00001
 * @tc.desc: Test RemoveCache with mixed reference scenarios
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(PixelMapCacheManagerTest, RemoveCache_MixedReferences_00001, Function | SmallTest | Level1)
{
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto pixelMap1 = CreateTestPixelMap();
    auto pixelMap2 = CreateTestPixelMap();
    auto pixelMap3 = CreateTestPixelMap();
    
    cacheManager->CachePixelMap("request1", "cache1", pixelMap1);
    cacheManager->CachePixelMap("request2", "cache1", pixelMap1);
    cacheManager->CachePixelMap("request1", "cache2", pixelMap2);
    cacheManager->CachePixelMap("request3", "cache3", pixelMap3);
    
    cacheManager->RemoveCache("request1");
    
    EXPECT_NE(cacheManager->globalCache_.find("cache1"), cacheManager->globalCache_.end());
    EXPECT_EQ(cacheManager->globalCache_.find("cache2"), cacheManager->globalCache_.end());
    EXPECT_NE(cacheManager->globalCache_.find("cache3"), cacheManager->globalCache_.end());
    
    cacheManager->RemoveCache("request2");
    EXPECT_EQ(cacheManager->globalCache_.find("cache1"), cacheManager->globalCache_.end());
    
    cacheManager->RemoveCache("request3");
    EXPECT_EQ(cacheManager->globalCache_.find("cache3"), cacheManager->globalCache_.end());
}

}  // namespace Notification
}  // namespace OHOS