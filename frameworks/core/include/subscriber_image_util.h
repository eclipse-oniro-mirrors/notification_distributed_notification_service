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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_CORE_INCLUDE_SUBSCRIBER_IMAGE_UTIL_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_CORE_INCLUDE_SUBSCRIBER_IMAGE_UTIL_H

#include <memory>
#include <string>
#include <vector>
#include "notification.h"
#include "picture_option.h"
#include "pixel_map.h"
#include "want_params.h"

namespace OHOS {
namespace Notification {
class SubscriberImageUtil {
public:
    static void ProcessPictureOption(
        const std::shared_ptr<Notification> &notification,
        const sptr<PictureOption> &pictureOption);

private:
    static std::unique_ptr<Media::PixelMap> GetPixelMapByRes(
        const sptr<NotificationRequest> &request,
        const std::string &resPath);
    
    static std::vector<std::string> GetPicPathsFromParam(
        const std::shared_ptr<AAFwk::WantParams>& extraInfo,
        const std::string& picPathKey);
    
    static bool ExtractFromString(
        const sptr<AAFwk::IInterface>& param,
        std::vector<std::string>& picPaths);
    
    static bool ExtractFromStringArray(
        const sptr<AAFwk::IInterface>& param,
        std::vector<std::string>& picPaths);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_CORE_INCLUDE_SUBSCRIBER_IMAGE_UTIL_H