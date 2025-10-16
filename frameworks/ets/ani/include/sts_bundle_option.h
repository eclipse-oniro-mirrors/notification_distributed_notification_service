/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_BUNDLE_OPTION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_BUNDLE_OPTION_H
#include "ani.h"
#include "distributed_bundle_option.h"
#include "notification_bundle_option.h"

using BundleOption = OHOS::Notification::NotificationBundleOption;
using DistributedBundleOption = OHOS::Notification::DistributedBundleOption;
namespace OHOS {
namespace NotificationSts {
bool UnwrapBundleOption(ani_env *env, ani_object param, BundleOption& option);
bool WrapBundleOption(ani_env* env,
    const std::shared_ptr<BundleOption> &bundleOption, ani_object &bundleObject);

bool UnwrapArrayBundleOption(ani_env *env, ani_ref arrayObj, std::vector<BundleOption>& options);
ani_object GetAniArrayBundleOption(ani_env* env, const std::vector<BundleOption> &bundleOptions);
bool UnwrapArrayDistributedBundleOption(ani_env *env, ani_object arrayObj,
    std::vector<DistributedBundleOption> &options);
}
}

#endif