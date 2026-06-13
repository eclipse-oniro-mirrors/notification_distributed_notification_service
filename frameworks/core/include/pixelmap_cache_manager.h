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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_CORE_INCLUDE_PIXELMAP_CACHE_MANAGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_CORE_INCLUDE_PIXELMAP_CACHE_MANAGER_H

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include "pixel_map.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {

class PixelMapCacheManager : public DelayedSingleton<PixelMapCacheManager> {
public:
    std::shared_ptr<Media::PixelMap> GetCachedPixelMap(
        const std::string& requestKey,
        const std::string& cacheKey);

    void CachePixelMap(
        const std::string& requestKey,
        const std::string& cacheKey,
        std::shared_ptr<Media::PixelMap> pixelMap);

    void RemoveCache(const std::string& requestKey);

private:
    std::map<std::string, std::set<std::string>> requestToCacheKeys_;
    std::map<std::string, std::shared_ptr<Media::PixelMap>> globalCache_;
    std::mutex mutex_;

    DECLARE_DELAYED_SINGLETON(PixelMapCacheManager)
};

}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_CORE_INCLUDE_PIXELMAP_CACHE_MANAGER_H