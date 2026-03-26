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
#include "sts_notification_statistics.h"

#include "sts_common.h"
#include "sts_bundle_option.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationSts {
bool WrapStatisticsInfo(ani_env* env,
    const std::shared_ptr<StatisticsInfo> &statistics, ani_object &statisticsObject)
{
    ANS_LOGD("WrapStatisticsInfo call");
    if (env == nullptr || statistics == nullptr) {
        ANS_LOGE("WrapStatisticsInfo failed, has nullptr");
        return false;
    }
    ani_class statisticsCls = nullptr;
    if (!CreateClassObjByClassName(env,
        "@ohos.notificationManager.notificationManager.NotificationStatisticsInner", statisticsCls, statisticsObject)
        || statisticsCls == nullptr || statisticsObject == nullptr) {
        ANS_LOGE("WrapStatisticsInfo: create statisticsInfo failed");
        return false;
    }

    ani_object bundleObject;
    std::shared_ptr<BundleOption> optionSp = std::make_shared<BundleOption>(statistics->GetBundleOption());
    if (!WrapBundleOption(env, optionSp, bundleObject) || bundleObject == nullptr) {
        ANS_LOGE("WrapReminderInfo: bundleObject is nullptr");
        return false;
    }
    if (!SetPropertyByRef(env, statisticsObject, "bundle", bundleObject)) {
        ANS_LOGE("Set bundle failed");
        return false;
    }
    if (!SetFieldLong(env, statisticsCls, statisticsObject, "lastTime", statistics->GetLastTime())) {
        ANS_LOGE("Set lastTime failed");
        return false;
    }
    if (!SetFieldInt(env, statisticsCls, statisticsObject, "recentCount", statistics->GetRecentCount())) {
        ANS_LOGE("Set recentCount failed");
        return false;
    }

    ANS_LOGD("WrapStatisticsInfo end");
    return true;
}

ani_object GetAniArrayStatisticsInfo(ani_env* env, const std::vector<StatisticsInfo> &statistics)
{
    ANS_LOGD("GetAniArrayStatisticsInfo call");
    if (env == nullptr) {
        ANS_LOGE("GetAniArrayStatisticsInfo failed, has nullptr");
        return nullptr;
    }
    ani_array arrayObj = newArrayClass(env, statistics.size());
    if (arrayObj == nullptr) {
        ANS_LOGE("GetAniArrayStatisticsInfo: arrayObj is nullptr");
        return nullptr;
    }
    int32_t index = 0;
    for (auto &item : statistics) {
        std::shared_ptr<StatisticsInfo> optSp = std::make_shared<StatisticsInfo>(item);
        ani_object itemObject;
        if (!WrapStatisticsInfo(env, optSp, itemObject) || itemObject == nullptr) {
            ANS_LOGE("GetAniArrayStatisticsInfo: item is nullptr");
            return nullptr;
        }
        if (ANI_OK != env->Array_Set(arrayObj, index, itemObject)) {
            ANS_LOGE("GetAniArrayReminderInfo: Array_Set failed");
            return nullptr;
        }
        index++;
    }
    ANS_LOGD("GetAniArrayStatisticsInfo end");
    return arrayObj;
}
}
}