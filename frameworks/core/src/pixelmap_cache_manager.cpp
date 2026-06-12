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

#include "pixelmap_cache_manager.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {

PixelMapCacheManager::PixelMapCacheManager()
{
}

PixelMapCacheManager::~PixelMapCacheManager()
{
    std::lock_guard<std::mutex> lock(mutex_);
    requestToCacheKeys_.clear();
    globalCache_.clear();
}

std::shared_ptr<Media::PixelMap> PixelMapCacheManager::GetCachedPixelMap(
    const std::string& requestKey,
    const std::string& cacheKey)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = globalCache_.find(cacheKey);
    if (it == globalCache_.end()) {
        return nullptr;
    }
    requestToCacheKeys_[requestKey].insert(cacheKey);
    ANS_LOGI("Cache hit for requestKey=%{public}s, cacheKey=%{public}s",
        requestKey.c_str(), cacheKey.c_str());
    return it->second;
}

void PixelMapCacheManager::CachePixelMap(
    const std::string& requestKey,
    const std::string& cacheKey,
    std::shared_ptr<Media::PixelMap> pixelMap)
{
    if (pixelMap == nullptr) {
        ANS_LOGI("Skip caching: pixelMap null");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = globalCache_.find(cacheKey);
    if (it != globalCache_.end()) {
        ANS_LOGI("PixelMap already cached: cacheKey=%{public}s, add reference for requestKey=%{public}s",
            cacheKey.c_str(), requestKey.c_str());
        requestToCacheKeys_[requestKey].insert(cacheKey);
        return;
    }
    globalCache_[cacheKey] = pixelMap;
    requestToCacheKeys_[requestKey].insert(cacheKey);
    ANS_LOGI("Cached new PixelMap for requestKey=%{public}s, cacheKey=%{public}s",
        requestKey.c_str(), cacheKey.c_str());
}

void PixelMapCacheManager::RemoveCache(const std::string& requestKey)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto reqIt = requestToCacheKeys_.find(requestKey);
    if (reqIt == requestToCacheKeys_.end()) {
        ANS_LOGI("No cache for requestKey=%{public}s", requestKey.c_str());
        return;
    }
    std::set<std::string> cacheKeys = reqIt->second;
    requestToCacheKeys_.erase(reqIt);
    for (const auto& cacheKey : cacheKeys) {
        bool hasOtherRef = false;
        for (const auto& reqEntry : requestToCacheKeys_) {
            if (reqEntry.second.find(cacheKey) != reqEntry.second.end()) {
                hasOtherRef = true;
                break;
            }
        }
        if (!hasOtherRef) {
            globalCache_.erase(cacheKey);
        }
    }
    ANS_LOGI("Removed request cache: requestKey=%{public}s, cleared %{public}zu cacheKeys",
        requestKey.c_str(), cacheKeys.size());
}
}  // namespace Notification
}  // namespace OHOS