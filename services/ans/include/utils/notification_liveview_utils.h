/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef NOTIFICATION_LIVEVIEW_UTILS_H
#define NOTIFICATION_LIVEVIEW_UTILS_H

#include <string>
#include <vector>
#include <map>
#include "ffrt.h"
#include "notification_request.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace Notification {

struct LiveViewCheckParam {
public:
    LiveViewCheckParam() = default;
    LiveViewCheckParam(const std::vector<std::string> bundles)
    {
        bundlesName = bundles;
    }
    int32_t retryTime = 0;
    std::vector<std::string> bundlesName;
};


class NotificationLiveViewUtils {
public:
    static NotificationLiveViewUtils& GetInstance();

    std::string AddLiveViewCheckData(std::shared_ptr<LiveViewCheckParam>& param);
    void EraseLiveViewCheckData(const std::string& requestId);
    bool GetLiveViewCheckData(const std::string& requestId, std::shared_ptr<LiveViewCheckParam>& data);
    bool CheckLiveViewConfigByBundle(const std::string& bundleName, const std::string& event);
    bool CheckLiveViewConfigByBundle(const std::string& bundleName, const std::string& event, int32_t userId);
    bool CheckLiveViewForBundle(const sptr<NotificationRequest>& request);

    bool CheckLiveViewVersion();
    void NotifyLiveViewEvent(const std::string& event);
    void NotifyLiveViewEvent(const std::string& event, const sptr<NotificationBundleOption>& bundleInfo);
    bool CheckLiveViewRebuild(int32_t userId);
    void SetLiveViewRebuild(int32_t userId, int32_t data);
    void RemoveLiveViewRebuild(int32_t userId);

    static const int32_t ERASE_FLAG_INIT = 0;
    static const int32_t ERASE_FLAG_RUNNING = 1;
    static const int32_t ERASE_FLAG_FINISHED = 2;
    static constexpr char ALL_EVENT[] = "ALL";
private:
    NotificationLiveViewUtils() = default;
    ~NotificationLiveViewUtils() = default;

    ffrt::mutex eraseMutex;
    std::map<int32_t, int32_t> eraseFlag;

    ffrt::mutex dataMutex;
    std::map<std::string, std::shared_ptr<LiveViewCheckParam>> checkData;
};

}
}
#endif // NOTIFICATION_LIVEVIEW_UTILS_H
