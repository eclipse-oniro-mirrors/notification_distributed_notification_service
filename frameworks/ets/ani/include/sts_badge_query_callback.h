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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_BADGEQUERY_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_BADGEQUERY_H

#include <future>
#include "ani.h"
#include "ffrt.h"
#include "ibadge_query_callback.h"
#include "badge_query_callback_stub.h"
#include "notification_constant.h"

namespace OHOS {
namespace NotificationSts {
using NotificationBundleOption = OHOS::Notification::NotificationBundleOption;

class StsBadgeQueryCallBack : public OHOS::Notification::BadgeQueryCallbackStub {
public:
    StsBadgeQueryCallBack() {};
    virtual ~StsBadgeQueryCallBack() {};
    ErrCode OnBadgeNumberQuery(const sptr<NotificationBundleOption>& bundleOption, int32_t &badgeNumber) override;
    void HandleBadgeQueryCallback(ani_env *env, std::vector<ani_ref> &param);
    ErrCode GetBadgeNumberQueryInfo(const sptr<NotificationBundleOption> &bundleOption,
        int32_t &uid, std::shared_ptr<StsBadgeQueryCallBack> &callback);
    bool SetObject(ani_env *env, ani_object obj);
    bool IsInit();
    void Clean(ani_env *env);

private:
    ani_ref ref_ = nullptr;
    ani_vm *vm_ = nullptr;
    ffrt::mutex callbackMutex_;
};

class StsBadgeQueryCallBackManager {
public:
    static StsBadgeQueryCallBackManager* GetInstance()
    {
        static StsBadgeQueryCallBackManager instance;
        return &instance;
    }
    ~StsBadgeQueryCallBackManager() = default;

    bool MakeBadgeQueryCallBackInfo(ani_env *env, ani_fn_object value,
        std::shared_ptr<StsBadgeQueryCallBack> &badgeQueryCallback);
    bool AddBadgeQueryCallBackInfo(int32_t userId,
        std::shared_ptr<StsBadgeQueryCallBack> &badgeQueryCallback);
    void DelBadgeQueryCallBackInfo(int32_t userId);
    std::shared_ptr<StsBadgeQueryCallBack> GetBadgeQueryCallbackInfo(int32_t userId);

    void AniOnBadgeNumberQuery(ani_env *env, ani_fn_object fn);
    void AniOffBadgeNumberQuery(ani_env *env);
    void AniHandleBadgeNumberPromise(ani_env *env, ani_object bundle, ani_long num);
private:
    StsBadgeQueryCallBackManager() {}
private:
    ffrt::mutex badgeQueryCallbackInfoMutex_;
    std::map<int32_t, std::shared_ptr<StsBadgeQueryCallBack>> badgeQueryCallbackInfos_;
};

class BadgeNumberPromiseManager {
public:
    static std::future<int32_t> CreatePromise(int32_t uid);
    static void SetValue(int32_t uid, int32_t value);
    static void RemovePromise(int32_t uid);
private:
    static ffrt::mutex promiseMutex_;
    static std::unordered_map<int32_t, std::shared_ptr<std::promise<int32_t>>> promises_;
};

} // namespace NotificationSts
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_BADGEQUERY_CALLBACK_H
