/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_BADGEQUERY_CALLBACK_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_BADGEQUERY_CALLBACK_H

#include <iremote_object.h>

#include "want.h"
#include "ffrt.h"
#include "parcel.h"
#include "common.h"
#include "ibadge_query_callback.h"
#include "badge_query_callback_stub.h"
#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"
#include "notification_constant.h"

namespace OHOS {
namespace NotificationNapi {
class JSBadgeQueryCallBack : public BadgeQueryCallbackStub, public std::enable_shared_from_this<JSBadgeQueryCallBack> {
public:
    JSBadgeQueryCallBack();
    virtual ~JSBadgeQueryCallBack();
    ErrCode OnBadgeNumberQuery(const sptr<NotificationBundleOption>& bundleOption, int32_t &badgeNumber) override;
    void SetThreadSafeFunction(const napi_threadsafe_function &tsfn);
    napi_threadsafe_function GetThreadSafeFunction();
    void SetEnv(const napi_env &env);
    void ClearEnv();
    napi_ref ref = nullptr;
private:
    ffrt::mutex tsfnMutex_;
    napi_env env_ = nullptr;
    napi_threadsafe_function tsfn_ = nullptr;
};

napi_value NapiOnBadgeNumberQuery(napi_env env, napi_callback_info info);
napi_value NapiOffBadgeNumberQuery(napi_env env, napi_callback_info info);
} // namespace Notification
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_BADGEQUERY_CALLBACK_H
