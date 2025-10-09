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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_PUSH_CALLBACK_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_PUSH_CALLBACK_H
#include <map>
#include "ani.h"
#include "ffrt.h"
#include "push_callback_stub.h"
#include "notification_constant.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace OHOS::Notification;
class StsPushCallBack : public PushCallBackStub {
public:
    struct ResultParam {
        int32_t code = -1;
        std::string msg = "";
    };

    StsPushCallBack(ani_env *env);
    virtual ~StsPushCallBack();
    int32_t OnCheckNotification(
        const std::string &notificationData, const std::shared_ptr<PushCallBackParam> &pushCallBackParam) override;
    void SetJsPushCallBackObject(ani_env *env, NotificationConstant::SlotType slotType, ani_ref pushCallBackObject);
    void HandleCheckCallback(
        ani_env *env, ani_fn_object fn, ani_object value, const std::shared_ptr<PushCallBackParam> &pushCallBackParam);

private:
    int32_t CheckNotification(
        ani_env *env,
        const std::string &notificationData,
        const std::shared_ptr<PushCallBackParam> &pushCallBackParam);
    static bool WarpFunctionResult(ani_env *env, ani_object funcResult, ResultParam &result);
    ani_vm *vm_ = nullptr;
    std::map<NotificationConstant::SlotType, ani_ref> pushCallBackObjects_;
    ffrt::mutex mutexlock;
};

} // namespace NotificationManagerSts
} // namespace OHOS
#endif

